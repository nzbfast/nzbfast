//! §282 alternate candidates, the user-facing half (section D).
//!
//! Three things live here, and they are one subject: the settings that
//! decide how many spares are held and whether anything happens without
//! being asked (item 13), the OFFER a queue row makes once the engine has
//! concluded a job cannot complete (item 12), and the switch itself,
//! which is what item 14's "say what happened" clause is written from.
//!
//! ## What this file does NOT do
//!
//! It never decides that a job is doomed. That verdict is §282 section A,
//! and this file only reads it: [`terminal_reason`] is the whole of the
//! coupling, one function with one arm today. Section A adds its own arm
//! there and every surface below - the queue row, the button, the history
//! clause, the report - renders it with no further edit.
//!
//! It never SEARCHES either. Finding a replacement nobody held is §282
//! section C (items 8-11), which carries the *arr ownership gate, the
//! age gate and the give-up breaker; a button here that quietly grew its
//! own search would be that section written without any of them. When
//! nothing is held the offer says so and names the setting that would
//! have held one, which is the honest answer and not a placeholder.
//!
//! ## Why nothing here acts on its own
//!
//! §282's default posture is a CLICK, because it is the only posture
//! that is safe on every account type: a switch spends a second copy of
//! the release, and on a block account that is money. `alt_auto_switch`
//! and `alt_auto_search` exist so an operator who has decided otherwise
//! can say so, and both are OFF.
//!
//! And nothing here may flip `post_health_fail`. Its OFF default is a
//! public commitment on issue #29 (§138), and the offer below is
//! deliberately the opposite trade: the same verdict, shown to the user
//! with a button, instead of a job ended on it.

use super::*;

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64};

/// §282 item 13. Five knobs, declared here: hold two spares and promote
/// one without asking, but never go hunting for a copy nobody held.
///
/// One struct rather than five fields on [`Daemon`] because these five
/// are only ever read together - a cost ceiling is not a cost ceiling if
/// the thing it bounds lives somewhere else - and because there is no
/// room for them there. `serve/daemon.rs` sits ONE line under its
/// size-gate ceiling, which is why the field over there is a single line
/// with a trailing comment rather than the doc-comment-plus-declaration
/// every other field has: two lines refuses the build. That is the
/// ratchet working as designed (the next change to that file has to
/// split it) and the reason every word of the argument lives here.
///
/// THE TWO DEFAULTS THIS FILE ONCE DEFERRED ARE DECIDED. §282 item 19
/// (24 Aug 2026): `alt_auto_switch` ships **ON** and `alt_hold_count`
/// ships **2** with it. The decision is recorded here rather than the
/// numbers simply being changed, because the argument outlives the
/// values and is the only thing that says whether a later tuning is a
/// tuning or a reversal.
///
/// THE ARGUMENT. The two opt-ins are NOT ALIKE IN COST, which is why
/// they do not get the same answer. Promoting a spare we ALREADY HOLD
/// spends no bytes beyond the payload the user asked for - the NZB is on
/// disk, the release is the one they chose, and the alternative to
/// promoting it is a failed job. Hunting spends NEW bytes on a search
/// they did not ask for, against a provider that may bill per byte. So
/// `alt_auto_search` stays **OFF** and must: it is the one of the two
/// that can cost money nobody agreed to.
///
/// The hold count is the third leg of that same argument and is
/// load-bearing rather than a taste: an ON switch with a ZERO hold count
/// has nothing to promote, so it would ship a default that reads as a
/// feature and behaves exactly as today. Two rather than three because
/// the second spare is already the long tail - the first alternate is
/// what fixes the common case, a release posted twice where one post is
/// bad. It is also not a second answer to `spare::SPARE_HOLD_COUNT`:
/// [`Default`] below is INITIALISED from that constant, so the
/// grab-time hold and the setting cannot disagree.
///
/// The settings copy deliberately states no default for either - the
/// control shows the live value, and copy that names a default is copy
/// that goes stale the day the default moves. Nothing in this file may
/// touch `post_health_fail`, which stays OFF (issue #29, §138).
pub struct AltSettings {
    /// `alt_hold_count`: ranked spares to hold per grab; 0 = off,
    /// suggested 2-3. Cheap even at 3 - it is NZB FILES only, a few
    /// kilobytes each, never payload. Read by §282 item 5's grab-time
    /// hold, which is the only thing that acts on it.
    pub hold_count: AtomicU32,
    /// `alt_auto_switch`: promote a held spare on a terminal verdict
    /// instead of asking. ON (§282 item 19, argument above).
    pub auto_switch: AtomicBool,
    /// `alt_auto_search`: hunt for a replacement when nothing is held.
    /// OFF, and gated by §282 section C's own rules on top of this -
    /// never for an *arr-origin job, never under the propagation age
    /// gate, and always counted against the §96.3 give-up breaker.
    pub auto_search: AtomicBool,
    /// `alt_max_copies`: how many copies of one release this whole
    /// mechanism may spend, the original included. Default 2.
    pub max_copies: AtomicU32,
    /// `alt_max_extra_bytes`: bytes an alternate may add on top of the
    /// original grab. 0 = unlimited, which is the right default on a
    /// flat-rate account and the wrong one on a metered block account -
    /// so this MUST be consulted before spending a spare on any server
    /// marked as a block account, whatever it is set to.
    pub max_extra_bytes: AtomicU64,
}

impl Default for AltSettings {
    fn default() -> Self {
        Self {
            // NOT a literal 2: `spare::SPARE_HOLD_COUNT` is what the
            // grab-time hold would use with no setting at all, so
            // initialising from it is what stops the two disagreeing.
            hold_count: AtomicU32::new(super::spare::SPARE_HOLD_COUNT as u32),
            auto_switch: AtomicBool::new(true),
            auto_search: AtomicBool::new(false),
            max_copies: AtomicU32::new(2),
            max_extra_bytes: AtomicU64::new(0),
        }
    }
}

/// A held row, snapshotted once per queue walk so the per-row offer
/// below is a filter over a small Vec rather than a second walk of the
/// queue under its own lock.
pub(super) struct HeldSpare {
    pub(super) nzo_id: String,
    pub(super) name: String,
    /// The job this row was held against, empty for a pre-`held_for`
    /// row - the same two-case shape `daemon_park::held_against` reads.
    pub(super) held_for: String,
    pub(super) dupe_key: Option<String>,
}

impl HeldSpare {
    /// Is this row held against `id` / `key`? The same question
    /// `daemon_park`'s promotion asks, and deliberately the same answer:
    /// a row the offer names must be a row the switch can promote.
    pub(super) fn held_against(&self, id: &str, key: Option<&str>) -> bool {
        if self.held_for.is_empty() {
            return key.is_some() && self.dupe_key.as_deref() == key;
        }
        self.held_for == id
    }
}

/// Why this job cannot complete: `(token, sentence, failure lead)`, or
/// None when nothing has concluded that it cannot.
///
/// THE TOKEN IS THE CONTRACT. The dashboard renders its own translated
/// sentence per token and falls back to the sentence here for one it
/// does not know, so a new verdict costs one arm here and one catalogue
/// key - and renders in English rather than not at all in the window
/// between the two.
///
/// THE THIRD FIELD IS A CLASSIFICATION, not prose. `failkind::fail_kind`
/// reads a failure message by PREFIX, so the lead decides what a switch
/// tells an *arr: `post is gone` maps to NZBGet's `FAILURE/HEALTH`,
/// which is what makes Sonarr blocklist the release and look for another
/// one, and it arms no automatic retry. That is exactly right for a job
/// the user has just replaced, and getting it wrong is not a wording
/// mistake - it is the *arr asking us for the same dead post again.
///
/// One arm today, and it is the only verdict on this tree that means
/// "no server can supply this": the §77 pre-flight sample, at the bar
/// §138 set for ending a release on it - every configured server
/// answered, every sampled article was missing, the post is past the
/// propagation age gate, and the user has not reordered the job since.
/// That bar is `post_health_fail`'s, and this reads it WITHOUT the
/// setting: the setting decides whether the daemon may end the job on
/// its own, and offering the user a button is not that.
///
/// WHICH IS WHY THIS DOES NOT CALL `health::giveup_reason`, though it
/// is built from the same three numbers. That sentence closes with
/// "failed without downloading because the \"give up on posts no server
/// can supply\" setting is on", which is true where it is used and
/// FALSE here twice over: the setting is off, and nothing has failed
/// yet. Measured on a live daemon 24 Aug 2026, which is how it was
/// caught - the queue row said the job had been failed by a setting the
/// same page showed switched off.
///
/// TWO ARMS, and the SECOND one is the incident this whole section was
/// written against. §282 section A's item 1 probes the PAR2 recovery set
/// separately from the payload, because the payload sampler skips
/// `Par2Volume` outright and therefore sampled the one half of that post
/// that was healthy - both jobs badged green with 99.2% and 99.8% of
/// their payload intact and the recovery set dead. `RecoveryHealth::
/// unobtainable` is that verdict at the same four-clause bar the payload
/// one uses, and the sentence it produces is the one §282 asks for by
/// name: the repair data cannot be fetched from your provider, not a
/// segment count.
///
/// The recovery arm is tried FIRST. When both fire the recovery one is
/// the more useful thing to say - "no server has this post" and "no
/// server will serve its repair data" are both true then, and only the
/// second explains why a post that looks nearly complete cannot be
/// finished.
///
/// Neither arm reads `post_health_fail`. That setting decides whether
/// the daemon may END a job on its own evidence; offering the user a
/// button is not that, and the setting stays OFF (issue #29, §138).
///
/// §282 section A's items 3 and 4 - the running projection and the
/// recovery-fetch yield gate - are the in-flight verdicts and are not
/// built yet. Each is one more arm here and nothing else.
pub(super) fn terminal_reason(j: &Job) -> Option<(&'static str, String, &'static str)> {
    let h = j.health.as_ref()?;
    if let Some(r) = h.recovery.as_ref().filter(|r| r.unobtainable()) {
        return Some((
            "recovery",
            format!(
                "the repair data for this post cannot be fetched from your provider: all {} \
                 sampled article(s) of its {} PAR2 file(s) are on none of your {} server(s), \
                 and the set is old enough that propagation no longer explains it. The \
                 payload may be nearly complete and still cannot be repaired",
                r.sampled, r.volumes, r.servers
            ),
            // A CLASSIFICATION, not prose: `fail_kind` reads this prefix
            // as PreflightImpossible, whose remedy is "grab another
            // release" and which arms no retry - which is exactly right
            // for a post whose parity is dead. (§282 item 17 is the item
            // that makes leads of this family read better; it owns
            // get/settle.rs and this is not it.)
            "pre-flight: articles missing beyond repair",
        ));
    }
    if !h.no_server_can_supply() {
        return None;
    }
    Some((
        "gone",
        format!(
            "all {} sampled article(s) were reported missing by every one of your {} \
             configured server(s), and at {} day(s) old the post is past the point where \
             propagation explains it",
            h.sampled, h.servers, h.age_days
        ),
        "post is gone",
    ))
}

/// The queue row's offer: the reason, and the spares that could be
/// switched to. `None` when nothing has concluded the job is doomed.
///
/// An offer with an EMPTY spare list is still an offer, and that is the
/// point: the notice is the half that was missing from the incident this
/// was designed against ("it never told me up front that it could not
/// finish"), and it is worth saying whether or not there is a button
/// beside it.
pub(super) fn offer_json(j: &Job, held: &[HeldSpare]) -> Option<Value> {
    let (token, why, _) = terminal_reason(j)?;
    let spares: Vec<Value> = held
        .iter()
        .filter(|s| s.held_against(&j.nzo_id, j.dupe_key.as_deref()))
        .map(|s| json!({"nzo_id": s.nzo_id, "name": s.name}))
        .collect();
    Some(json!({"reason": token, "detail": why, "spares": spares}))
}

impl Daemon {
    /// Every row parked as a held alternative, snapshotted under one
    /// queue lock. Empty on the overwhelmingly common install, where
    /// nothing is held at all.
    pub(super) fn alt_held_spares(&self) -> Vec<HeldSpare> {
        self.queue
            .lock_ok()
            .iter()
            .filter_map(|j| {
                let g = j.lock_ok();
                (g.priority == -3 && g.paused && !g.tombstone).then(|| HeldSpare {
                    nzo_id: g.nzo_id.clone(),
                    name: g.name.clone(),
                    held_for: g.held_for.clone(),
                    dupe_key: g.dupe_key.clone(),
                })
            })
            .collect()
    }

    /// §282 item 12: switch `failed_id` for the held spare `spare_id`.
    ///
    /// Returns the error to show the user, or None on success. Every
    /// refusal names what to do instead; none of them is a state the
    /// dashboard can reach by drawing what the queue told it, so a
    /// refusal here means the queue moved under the tab.
    ///
    /// The original is FAILED rather than deleted, and the reason it
    /// carries is the verdict's own sentence. That is what puts both
    /// attempts in history (item 14) - a delete files a "deleted from
    /// the queue" row that says nothing about why, and the user reading
    /// it in a week is exactly the reader item 14 exists for.
    ///
    /// Not offered on a job that is DOWNLOADING or FINISHING: the runner
    /// owns that record and files it itself. The verdict this reads is
    /// taken while the queue is idle, so the row it appears on is a
    /// queued one; refusing the race is cheaper than winning it.
    pub(super) fn alt_switch(&self, failed_id: &str, spare_id: &str) -> Option<String> {
        // Both rows, the two mutations and the queue removal under ONE
        // hold, so nothing can promote, delete or pick either half in
        // between. The history push and the durable write happen after
        // it, which is the order every other park on this tree takes.
        let held_writes = Daemon::hold_queue_writes();
        let orig = {
            let mut q = self.queue.lock_ok();
            let find = |id: &str| -> Option<Arc<Mutex<Job>>> {
                q.iter().find(|j| j.lock_ok().nzo_id == id).cloned()
            };
            let Some(orig) = find(failed_id) else {
                return Some("that download is no longer in the queue".into());
            };
            let Some(spare) = find(spare_id) else {
                return Some("that alternate is no longer in the queue".into());
            };
            let (verdict, key, name, running) = {
                let g = orig.lock_ok();
                (
                    terminal_reason(&g),
                    g.dupe_key.clone(),
                    g.name.clone(),
                    matches!(g.state, JobState::Downloading | JobState::Finishing),
                )
            };
            if running {
                return Some(
                    "this download has already started - pause it first, or let it finish".into(),
                );
            }
            let Some((_, why, lead)) = verdict else {
                return Some("nothing has concluded that this download cannot finish".into());
            };
            let spare_name = {
                let mut sg = spare.lock_ok();
                let is_spare = sg.priority == -3
                    && sg.paused
                    && !sg.tombstone
                    && (sg.held_for == failed_id
                        || (sg.held_for.is_empty() && key.is_some() && sg.dupe_key == key));
                if !is_spare {
                    return Some("that alternate is not being held for this download".into());
                }
                // The spare carries where it came from: this IS item
                // 14's clause, and it is written here rather than
                // derived later because the original leaves the queue on
                // the next line and its name is the part the user needs.
                sg.paused = false;
                sg.priority = 0;
                sg.held_for.clear();
                sg.alt_from = failed_id.to_string();
                sg.alt_from_name = name;
                sg.alt_why = why.clone();
                sg.name.clone()
            };
            {
                let mut g = orig.lock_ok();
                g.state = JobState::Failed;
                g.paused = false;
                g.priority = 0;
                // The LEAD, not the bare sentence: `fail_kind` reads
                // this by prefix, and it is what tells an *arr to
                // blocklist the release and search for another one
                // rather than hand us the same dead post back.
                g.fail_message = crate::with_build(format!("{lead}: {why}"));
                g.alt_to_name = spare_name.clone();
                g.finished_at = Some(Instant::now());
                g.finished_unix = Some(unix_now());
            }
            q.retain(|j| !Arc::ptr_eq(j, &orig));
            info!(
                target: "queue",
                "{spare_id} promoted by hand as an alternate for {failed_id} ({spare_name:?})"
            );
            orig
        };
        self.history.lock_ok().push(orig.clone());
        drop(held_writes);
        let _ = self.history_upsert(std::slice::from_ref(&orig));
        self.save_queue();
        self.life_emit_parked(&orig);
        self.history_enforce_retention();
        None
    }
}

/// A failure sentence with `diag::with_build`'s ` [nzbfast x.y.z]`
/// suffix taken back off.
///
/// The suffix belongs on a message somebody pastes into a bug report,
/// which is what `fail_message` is for. It does not belong in the middle
/// of "replaced X because Y", where it reads as noise about the wrong
/// build - the version that matters to that sentence is the one running
/// now, and the report prints it at the top.
pub(super) fn why_from_fail(msg: &str) -> String {
    match msg.rfind(" [nzbfast ") {
        Some(i) if msg.ends_with(']') => msg[..i].to_string(),
        _ => msg.to_string(),
    }
}

/// §282 item 14, the report's clause: what was tried, why it was
/// abandoned, what replaced it. Empty when this job neither replaced
/// another nor was replaced.
///
/// Plain text and assembled here rather than in `report.rs` so the
/// history row, the drawer and the report cannot drift into three
/// different accounts of one switch.
pub(super) fn switch_lines(j: &Job) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    if !j.alt_from_name.is_empty() {
        out.push(("replaced", j.alt_from_name.clone()));
        out.push(("replaced because", j.alt_why.clone()));
    }
    if !j.alt_to_name.is_empty() {
        out.push(("replaced by", j.alt_to_name.clone()));
    }
    out
}
