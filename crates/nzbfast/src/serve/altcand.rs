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
    ///
    /// That sentence was a promise nothing kept until §290: the hunt
    /// consulted it and `daemon_park::promote_held_alternative` did not,
    /// which is the one door that ships ON. `serve/altspend.rs` is where
    /// both roads now ask.
    pub max_extra_bytes: AtomicU64,
    /// §290: the admission gate, taken by every door that spends a copy
    /// and held across the ledger read AND the publication.
    ///
    /// It lives beside the two ceilings for the reason the struct's own
    /// header gives about them: a ceiling checked without one is not a
    /// ceiling, only a suggestion, because two doors can both read the
    /// spend before either has published. It guards no data of its own,
    /// which is why it is `Mutex<()>` - the ledger it serializes is the
    /// QUEUE, derived at every admission rather than stored, so there is
    /// nothing here to leak. See `altspend`'s header.
    pub(super) admit: Mutex<()>,
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
            admit: Mutex::new(()),
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
    if h.no_server_can_supply() {
        return Some((
            "gone",
            format!(
                "all {} sampled article(s) were reported missing by every one of your {} \
                 configured server(s), and at {} day(s) old the post is past the point where \
                 propagation explains it",
                h.sampled, h.servers, h.age_days
            ),
            "post is gone",
        ));
    }
    // THIRD ARM, §294: the joint verdict. The two above see the total
    // losses - a dead recovery set, a wholly gone post - and this one
    // sees the partial loss that is still past saving: enough sampled
    // articles missing that, projected over the post, the damage
    // exceeds what the declared PAR2 recovery can fund even at the
    // optimistic end of the confidence interval (`score_completable`'s
    // `No` is exactly that claim, and nothing weaker reaches here -
    // `Doubtful` offers nothing). Ordered LAST so a total loss keeps
    // its sharper sentence. Same classification prefix as the recovery
    // arm: the remedy is another release, and no retry can help.
    //
    // AND BEHIND THE SAME AGE GATE AS ITS SIBLINGS (release-eve sweep
    // S4, 25 Aug 2026). Both arms above only fire through Red, and Red
    // requires the post to be past `GONE_MIN_AGE_DAYS` - below that,
    // `health::score`'s own Amber sentence calls the identical evidence
    // "a warning and nothing more", because a post still propagating
    // looks exactly like a short one. `score_completable` never reads
    // the age (deliberately: the VERDICT "this sample projects past
    // recovery" is an honest statement about the sample at any age, and
    // the drawer may keep rendering it), so without this clause an *arr
    // grab minutes after upload could sprout copy asserting the sampled
    // articles "are gone" and a class saying no retry can help - and a
    // click on that button fails a job that would have completed. The
    // gate lives here, on the OFFER, because the offer copy is the
    // overclaim; `h.age_days` is the payload sample's own age, the same
    // figure Red is gated on for the arm above. (The RECOVERY set's own
    // age is the scorer's problem, and handled there since the S4
    // follow-on: a young-and-absent recovery sample cannot fund a `No`,
    // so that shape reads `doubtful` and never reaches this arm.)
    if h.completable == Some(crate::health::Completable::No)
        && h.age_days >= crate::diag::GONE_MIN_AGE_DAYS
    {
        return Some((
            "short",
            format!(
                "this post is missing more than its repair data can rebuild: {} of {} \
                 sampled article(s) are gone, and projected over the whole post that \
                 damage exceeds the PAR2 recovery declared for it",
                h.absent, h.sampled
            ),
            "pre-flight: articles missing beyond repair",
        ));
    }
    None
}

/// The queue row's offer: the reason, the spares that could be switched
/// to, and whether the row may ask for a search. `None` when nothing has
/// concluded the job is doomed.
///
/// An offer with an EMPTY spare list is still an offer, and that is the
/// point: the notice is the half that was missing from the incident this
/// was designed against ("it never told me up front that it could not
/// finish"), and it is worth saying whether or not there is a button
/// beside it.
///
/// **`search` and `auto` are §282 item 20**, which closed the seam
/// between this file and `serve/hunt.rs`. Item 12 said that with nothing
/// held the button "searches and shows what it found, ranked, for the
/// user to pick" and deliberately did not build it; section C then built
/// the automatic road only, so a user with nothing held was handed a
/// sentence naming a setting and no way to ask. Two booleans, because
/// both answers are the daemon's and neither can be derived in the page:
///
/// * `search` - may this row ask? False on an *arr-origin job, where
///   `hunt_gates` refuses on item 9's rule. Sent so the drawer can say
///   why instead of drawing a button that answers with a refusal.
/// * `auto` - is `alt_auto_search` on? It changes what the empty case
///   MEANS. Off, nothing further will happen unless the user acts; on, a
///   search will be tried when the job finally fails. The old copy named
///   only the hold setting, which read as "nothing else can happen" from
///   the day section C landed.
pub(super) fn offer_json(j: &Job, held: &[HeldSpare], auto_search: bool) -> Option<Value> {
    // A HELD row never carries the offer, whatever its health says.
    // Unreachable before §295 - held rows were never probed, so they
    // had no health for `terminal_reason` to read - and reachable the
    // day the prober started visiting them: a held spare of a dead
    // post would sprout "cannot finish" with a search button, on a row
    // that is not downloading anything. Its dead-ness is already
    // expressed where §295 designed it to be: the health badge on the
    // row, and the promotion band that ranks it last. Hunting a
    // replacement FOR A SPARE is §4b's junk-queue class - the spare
    // exists to catch its primary's failure, and if it is promoted and
    // then proves dead, THAT run gets the offer as an ordinary row.
    if !j.held_for.is_empty() {
        return None;
    }
    let (token, why, _) = terminal_reason(j)?;
    let spares: Vec<Value> = held
        .iter()
        .filter(|s| s.held_against(&j.nzo_id, j.dupe_key.as_deref()))
        .map(|s| json!({"nzo_id": s.nzo_id, "name": s.name}))
        .collect();
    Some(json!({
        "reason": token,
        "detail": why,
        "spares": spares,
        "search": !is_arr_origin(&j.origin),
        "auto": auto_search,
    }))
}

/// §284: may a row that has ALREADY FAILED still be offered another
/// copy?
///
/// [`offer_json`] above answers for a queue row, off `terminal_reason`,
/// because there nothing has failed yet and the pre-flight verdict is
/// the only evidence there is. The moment `daemon_park::park_gen` runs,
/// that row leaves the queue and the whole of §282 section D went with
/// it - the notice, both buttons and the switch itself all resolved
/// against `d.queue` alone. This is the same question asked of the
/// history record, and it is asked of the FAILURE rather than of the
/// health probe: the job really did fail, so its `fail_message` is the
/// verdict, exactly as it is for `hunt::Daemon::hunt_request`'s
/// automatic road. A pre-flight verdict that survived the park is not
/// needed and is not read - which is what makes this reach the shape
/// §284 item 2 is actually about, a job that died DURING the run with
/// no health probe on it at all.
///
/// **HOW FAR BACK, which §284 asks to be decided deliberately rather
/// than by a number somebody picked.** Every clause below is a
/// mechanism and none of them is an age:
///
/// 1. `failkind::another_copy_can_help` must say yes. THIS CLAUSE WAS
///    `fail_action == "search"` UNTIL TODO 305, and the swap is the
///    section's own repair rather than a loosening, so the argument for
///    both spellings belongs here.
///
///    The old rule read the retry surface's test - the rows whose Retry
///    is dimmed with "asking again cannot fix this one - the post is the
///    problem, not the download", which already carry a `find another`
///    button into a manual search - on the reasoning that a ranked
///    one-click replacement must not be offered on a NARROWER set than
///    the hand search beside it, nor on a WIDER one. That parity was a
///    good instinct and it borrowed the wrong predicate. Round B
///    measured what it cost (26 Aug 2026,
///    `research/RECOVERY-LADDER-YIELD-2026-08-26.md`): of twelve
///    failures, SEVEN where another release is the only remedy the
///    product has were told to retry, and they are one shape - a payload
///    that arrived all but whole over a recovery set no server would
///    serve. That is TODO 282's founding incident, and item 2 of THIS
///    section names it as the case the parked surface was built for. The
///    gate excluded it because `incomplete_reason` must open "download
///    incomplete" for the age gate's sake (TODO 283 item 13), so the
///    kind is `MissingArticles` and the action is `retry`.
///
///    `fail_action` was NOT widened to fix that, and must not be: the
///    dashboard's dimmed Retry hangs off it and `history_json` derives
///    SAB's `retry` BOOLEAN from `== "retry"`, so moving this family
///    would tell every *arr, nzb360 and LunaSea client that a row a
///    journal-resume retry can still shorten may not be asked for again.
///    The two questions are different - "what should this person press"
///    against "can another copy of this release help" - and the second
///    is answerable from the failure's own evidence. So it has its own
///    predicate, which is a strict superset of the old one plus exactly
///    the recovery-set family, and the parity that clause was reaching
///    for is preserved where it actually matters: the OFFER and the
///    clicked hunt still ask one predicate, so a button that is on the
///    page is a button `hunt_parked_request` will answer.
/// 2. The spooled `.nzb` must still be on disk. Not decoration: the
///    hunt's age gate reads it when the failure sentence carries no age
///    clause, and `hunt_pick`'s item 6 admission test reads it to
///    refuse a copy that is the SAME POST. Without it the pick can only
///    ever refuse, and a button that answers with a refusal is the one
///    thing `hunt_gates`' *arr arm refuses to ship. In practice this is
///    also the real age bound, because the spool is what a reaped
///    record loses.
/// 3. No auto-retry may be armed and still in the future. `park_gen`
///    guards BOTH the promotion and the hunt on `!armed_auto_retry` for
///    one reason: the original is coming back through the queue in
///    minutes and has not finished failing. A button offered inside
///    that window spends a copy on a job that is about to try again.
///    Tested against the clock rather than on presence, matching the
///    dashboard's own armed test - a stamp in the past means the retry
///    never ran, and that is not a reason to withhold the offer for
///    good.
/// 4. Nothing has replaced it already (`alt_to_name`). Item 14's stamp
///    IS the record that this switch happened; offering again would
///    spend a third copy of one release and write a second account of
///    one event over the first.
///
/// A tombstone is the user's own delete rather than a failure, the same
/// exclusion `park_gen` makes at every one of these decisions.
pub(super) fn parked_replaceable(j: &Job) -> bool {
    j.state == JobState::Failed
        && !j.tombstone
        && j.alt_to_name.is_empty()
        // `unsigned_abs` because the stamp is unix SECONDS in a u64 and
        // `unix_now` hands back an i64; the two are the same number on
        // every clock this runs on.
        && !j.auto_retry_at.is_some_and(|t| t > unix_now().unsigned_abs())
        && another_copy_can_help(
            j.fail_kind(),
            fail_hint(&j.fail_message),
            &j.fail_message,
            j.password_required,
        )
        && j.nzb_path.is_file()
}

/// §284: the same offer, on the history row of a job that has already
/// failed. `None` when [`parked_replaceable`] says another copy is not
/// the move for this record.
///
/// TWO KEYS AND NOT FOUR, and each absence is a decision rather than an
/// omission:
///
/// * no `reason`/`detail`. The queue row has nowhere else to say why it
///   cannot finish, so [`offer_json`] carries the verdict; the history
///   drawer prints the record's own Reason line, its fail_kind guidance
///   and its full attempt log above this block already. A third
///   paraphrase of one failure is what the drawer does not need.
/// * no `auto`. On a queue row that boolean says what will happen when
///   the job finally fails. This job HAS failed: with `alt_auto_search`
///   on, `park_gen` already asked - so "one will be searched for" is
///   not a promise that can still be kept, it is a description of
///   something that has already happened and come back empty.
pub(super) fn parked_offer_json(j: &Job, held: &[HeldSpare]) -> Option<Value> {
    if !parked_replaceable(j) {
        return None;
    }
    let spares: Vec<Value> = held
        .iter()
        .filter(|s| s.held_against(&j.nzo_id, j.dupe_key.as_deref()))
        .map(|s| json!({"nzo_id": s.nzo_id, "name": s.name}))
        .collect();
    Some(json!({
        "spares": spares,
        "search": !is_arr_origin(&j.origin),
    }))
}

/// The original half of a switch, read once from whichever store holds
/// it.
///
/// §284's whole shape in one struct: the two roads differ in what they
/// have to DO to the abandoned row, not in what they say about it.
struct SwitchFrom {
    job: Arc<Mutex<Job>>,
    /// The release being abandoned, for item 14's clause.
    name: String,
    /// Its dupe key, for the pre-`held_for` spare shape.
    key: Option<String>,
    /// Item 14's `alt_why`: why this attempt was abandoned, stripped of
    /// the build stamp.
    why: String,
    /// The failure LEAD to stamp, or `None` when the row has already
    /// failed and carries its own sentence. `Some` is the whole of the
    /// difference between the two roads: it means "this row is still on
    /// the queue, so failing it is this switch's job".
    lead: Option<&'static str>,
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

    /// §284: is `target` a HISTORY record a spare may still be held
    /// against?
    ///
    /// `daemon_enqueue::enqueue_as` refuses an add whose `hold_for`
    /// names no queue row, and it is right to: a spare whose job is
    /// gone is a download NOBODY asked for, which is the one thing a
    /// spare may never become. Every spare had a QUEUE row for an owner
    /// until `hunt::Daemon::hunt_pick` learned to run on a job that has
    /// already failed - it parks the picked copy as a spare of the
    /// doomed row for the instant it takes [`Daemon::alt_switch`] to
    /// promote it, and on that road the doomed row is in history. The
    /// pick therefore failed at the add, with a sentence about a delete
    /// that had not happened.
    ///
    /// [`parked_replaceable`] and not a bare "is it in history": it is
    /// the same predicate the drawer's offer and both clicked doors are
    /// drawn from, so this refusal has not loosened by a single record.
    /// A job that was deleted, completed, retried or already replaced is
    /// refused exactly as it was before.
    ///
    /// Called with the queue lock HELD, which is the queue -> history
    /// order `enqueue_as` already takes on its duplicate arm - the
    /// argument that it cannot ABBA is written out there, and nothing in
    /// `serve/` holds history and then reaches for the queue.
    pub(super) fn parked_spare_owner(&self, target: &str) -> bool {
        self.history.lock_ok().iter().any(|j| {
            let g = j.lock_ok();
            g.nzo_id == target && parked_replaceable(&g)
        })
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
    ///
    /// **TWO ROADS SINCE §284, and the second one is a HISTORY ROW.**
    /// Until 24 Aug 2026 this resolved both ids against `d.queue` and
    /// answered "that download is no longer in the queue" otherwise, so
    /// the whole of §282 section D vanished the instant
    /// `daemon_park::park_gen` retained the failed job out of the queue
    /// - including, on an install with `alt_auto_switch` off, a spare
    /// still parked at priority -3 that nothing would ever promote,
    /// offer or drop. The parked road is what makes
    /// `daemon_park::spare_held_for`'s and `promote_held_alternative`'s
    /// doc blocks true: the notice really does offer it on a click, on
    /// the abandoned job's history row.
    ///
    /// The two differ in exactly three things, all of them because the
    /// parked row has ALREADY FAILED: the verdict comes from its own
    /// `fail_message` rather than from `terminal_reason`, nothing about
    /// the row is restamped beyond item 14's `alt_to_name`, and
    /// `job.failed` is not re-emitted. See [`parked_replaceable`] for
    /// which parked rows qualify and why the bound is drawn where it is.
    ///
    /// **IT ANNOUNCES THE SWITCH, and until 24 Aug 2026 it did not.**
    /// Item 18 gave the switch its own lifecycle kind so that a user who
    /// is not looking at the dashboard is told, and wired it to the
    /// AUTOMATIC promote only (`Daemon::promote_held_alternative`). This
    /// door does the same job on a click - fails the original, unpauses
    /// the spare, stamps both halves of item 14's clause - and emitted
    /// nothing but `life_emit_parked`, which on a Failed row resolves to
    /// a bare `job.failed`. So the same outcome reached a `job.*`
    /// subscriber in two vocabularies, and the QUIETER one was the case
    /// where a switch is known for certain rather than inferred from a
    /// rank. Both now emit `job.switched` with the same keys, plus `by`
    /// (`"user"` here, `"auto"` there) to tell the doors apart; `rank` is
    /// the automatic door's only and is OMITTED here rather than nulled,
    /// because a clicked switch IS the user overriding the ranking. The
    /// whole argument, and the one place to change it, is the doc block
    /// on `promote_held_alternative`.
    ///
    /// A THIRD DOOR carries these same keys under a DIFFERENT kind:
    /// `hunt::hunt_enqueue`'s `job.replaced`, `by: "hunt"`. Item 18
    /// settled that on 24 Aug 2026 - one payload shape, two kinds,
    /// because a hunt spends new bytes and a target's `events` field can
    /// only filter on the kind. So an edit to the keys assembled below
    /// is an edit to three sites, not two.
    ///
    /// The five refusal arms return BEFORE any of this and emit nothing,
    /// which is the point: none of them changed a job, so there is no
    /// switch to announce.
    pub(super) fn alt_switch(&self, failed_id: &str, spare_id: &str) -> Option<String> {
        // §290 (Codex F-09/F-11). The gate is taken FIRST and held to
        // the end of the switch, so the ceilings are read and the spare
        // is unpaused without the automatic promotion or a hunt slipping
        // a second copy in between. It also carries `hunt::hunt_pick`'s
        // post-fetch weighing: that road parks its fetched copy as a
        // held spare and promotes it through here, so the size checked
        // is the parsed NZB's and not the indexer's advertisement.
        let _gate = self.alt_gate();
        if let Some(no) = self.alt_switch_admit(failed_id, spare_id) {
            return Some(no);
        }
        // §284: the original may be a HISTORY row, and it is resolved
        // BEFORE the queue lock is taken rather than inside the hold
        // below. `history_job` takes the history mutex, and nothing on
        // this tree takes those two nested - `park_gen` retains the
        // queue and pushes to history as two separate holds for the same
        // reason. The two races that opens are both benign and both end
        // in a refusal the user answers by clicking again: a row that
        // parks in the gap loses its queue entry and is not yet in
        // `parked`, and one that is RETRIED in the gap is found in the
        // queue below, which wins.
        let parked = self.history_job(failed_id);
        // Both rows, the two mutations and the queue removal under ONE
        // hold, so nothing can promote, delete or pick either half in
        // between. The history push and the durable write happen after
        // it, which is the order every other park on this tree takes.
        let held_writes = Daemon::hold_queue_writes();
        let (orig, switched, was_queued) = {
            let mut q = self.queue.lock_ok();
            let find = |id: &str| -> Option<Arc<Mutex<Job>>> {
                q.iter().find(|j| j.lock_ok().nzo_id == id).cloned()
            };
            let from = match find(failed_id) {
                // THE QUEUE ROAD (§282 item 12). Nothing has failed yet,
                // so the pre-flight verdict is the only evidence there
                // is - and failing the row is this switch's job.
                Some(orig) => {
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
                            "this download has already started - pause it first, or let it finish"
                                .into(),
                        );
                    }
                    let Some((_, why, lead)) = verdict else {
                        return Some(
                            "nothing has concluded that this download cannot finish".into(),
                        );
                    };
                    SwitchFrom {
                        job: orig,
                        name,
                        key,
                        why,
                        lead: Some(lead),
                    }
                }
                // THE PARKED ROAD (§284). The job HAS failed, so its own
                // `fail_message` is the verdict - the same evidence
                // `promote_held_alternative` reads on the automatic
                // road, and for the same reason. There is no queue row
                // to fail, no `finished_*` to stamp and no history push
                // to make: everything except item 14's `alt_to_name` has
                // already happened, which is why §284 says this switch
                // has LESS to do rather than more.
                None => {
                    let Some(orig) = parked else {
                        return Some("that download is no longer in the queue".into());
                    };
                    let (ok, key, name, why) = {
                        let g = orig.lock_ok();
                        (
                            parked_replaceable(&g),
                            g.dupe_key.clone(),
                            g.name.clone(),
                            why_from_fail(&g.fail_message),
                        )
                    };
                    if !ok {
                        return Some("another copy is no longer offered for that download".into());
                    }
                    SwitchFrom {
                        job: orig,
                        name,
                        key,
                        why,
                        lead: None,
                    }
                }
            };
            let SwitchFrom {
                job: orig,
                name,
                key,
                why,
                lead,
            } = from;
            let Some(spare) = find(spare_id) else {
                return Some("that alternate is no longer in the queue".into());
            };
            let (spare_name, spare_category) = {
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
                sg.alt_from_name = name.clone();
                sg.alt_why = why.clone();
                (sg.name.clone(), sg.category.clone())
            };
            // The failed row's own sentence, read back out AFTER it is
            // stamped: `job.switched` carries the raw `fail_message`
            // (build stamp and all) because that is what an operator
            // pastes into a bug report, and the automatic door carries
            // exactly the same string for exactly that reason.
            //
            // On the PARKED road there is nothing to stamp: the row
            // failed hours ago and its sentence is the one the drawer,
            // the report and every *arr have already read. Rewriting it
            // now would move a record's verdict under readers who have
            // already acted on it, and re-stamping `finished_unix` would
            // move the row to the top of a history sorted by when things
            // finished. Only `alt_to_name` is owed, which is item 14's
            // half that cannot be known any earlier.
            let reason = {
                let mut g = orig.lock_ok();
                if let Some(lead) = lead {
                    g.state = JobState::Failed;
                    g.paused = false;
                    g.priority = 0;
                    // The LEAD, not the bare sentence: `fail_kind` reads
                    // this by prefix, and it is what tells an *arr to
                    // blocklist the release and search for another one
                    // rather than hand us the same dead post back.
                    g.fail_message = crate::with_build(format!("{lead}: {why}"));
                    g.finished_at = Some(Instant::now());
                    g.finished_unix = Some(unix_now());
                }
                g.alt_to_name = spare_name.clone();
                // The auto-retry stamp goes with it. `parked_replaceable`
                // deliberately admits a row whose stamp is already PAST
                // due (clause 3), which is the very state a busy or held
                // daemon leaves it in, so a record something has just
                // replaced would otherwise come back through the queue on
                // a stamp that never fired - downloading the same release
                // a second time beside its replacement, and taking item
                // 14's "replaced by" row out of history on the way. The
                // queue road needs no such line: it re-parks the row
                // itself.
                g.auto_retry_at = None;
                g.auto_retry_why = None;
                g.fail_message.clone()
            };
            let was_queued = lead.is_some();
            if was_queued {
                q.retain(|j| !Arc::ptr_eq(j, &orig));
            }
            // The spares that were NOT picked are still held against a
            // job that is now finished with, on BOTH roads: the queue
            // road just retained it out of the queue, and the parked one
            // stamps `alt_to_name` above, which is what
            // `parked_replaceable` reads to stop offering that record a
            // second copy. Either way `held_against` can never match them
            // again - nothing promotes them, nothing offers them and
            // nothing drops them. So point them at the row that took its
            // place, exactly as `promote_held_alternative` does on the
            // automatic road: a grab that held two spares must not try
            // only one because the user clicked rather than waited.
            //
            // INSIDE the hold, and via the free function rather than
            // `Daemon::repoint_spares`, which takes this same lock. That
            // closes the window as well as the deadlock: at the instant
            // this guard drops, every loser already names the winner, so
            // `drop_stranded_spares` can never see one of them pointing
            // at a row that has left the queue and is not yet in history.
            //
            // The winner is not among them - `held_for` was cleared and
            // its priority raised above - and neither is a duplicate the
            // USER queued, which keeps naming what it was added against.
            let repointed = spare::repoint_spares_in(q.iter(), failed_id, spare_id);
            info!(
                target: "queue",
                "{spare_id} promoted by hand as an alternate for {failed_id} ({spare_name:?})"
            );
            if repointed > 0 {
                info!(target: "queue", "{repointed} spare(s) now held against {spare_id}");
            }
            // Assembled here, from strings that are already owned
            // clones, so the emit below is a move of a finished value
            // and provably acquires nothing on its way to the ring.
            let switched = json!({
                "nzo_id": spare_id,
                "name": spare_name,
                "category": spare_category,
                "replaces": failed_id,
                "replaces_name": name,
                "reason": reason,
                "by": "user",
            });
            (orig, switched, was_queued)
        };
        if was_queued {
            self.history.lock_ok().push(orig.clone());
        }
        drop(held_writes);
        if was_queued {
            // QUEUE -> history, so there is no `park_prewrite` behind
            // this one and no second chance after it: the row was pushed
            // into `self.history` above and this is the only write that
            // will ever put it on disk. Its answer was dropped by a
            // semicolon, so a store that refused the append left the
            // original in memory and nowhere else, under a switch the
            // user had already been told happened - the record would come
            // back at the next start as a QUEUED job, beside the
            // alternative that replaced it. `history_publish` rescues the
            // refused append with the rewrite and names the cost when it
            // cannot, and its present-check is the same guard the arm
            // below already takes for the same reason.
            self.history_publish(&orig, || {
                format!(
                    "{}: the replaced job's history row did not reach the store - \
                     after a restart it comes back as a queued job beside the \
                     alternative that replaced it",
                    orig.lock_ok().name
                )
            });
        } else {
            // `history_publish`, whose present-check is the same guard
            // `promote_held_alternative` takes for the same reason: a
            // delete landing between the read above and this write must
            // not resurrect the record. The rescuing publish and not the
            // raw upsert because the stamp above DISARMED a PAST-DUE
            // auto-retry (clause 3 admits one), so a refused append the
            // rewrite could still rescue would reload the stamp at the
            // next start and queue the parked row again beside the
            // alternative that replaced it (Codex C11).
            self.history_publish(&orig, || {
                format!(
                    "{}: the replaced row's disarmed retry did not reach the \
                     store - after a restart its overdue auto-retry queues it \
                     again beside the alternative",
                    orig.lock_ok().name
                )
            });
        }
        self.save_queue();
        // Both events, and in this order. `job.failed` is what the
        // original row IS now, and every existing subscriber keys on it;
        // `job.switched` is what HAPPENED, and is the only one of the two
        // that names the replacement. A target subscribed to `job.*` gets
        // both and can tell one switch from two unrelated jobs by
        // `replaces`. Neither may run under a job mutex - `life_emit`
        // takes the ring lock and then offers the event to the webhook
        // dispatcher - and neither does: `held_writes` is dropped above,
        // `life_emit_parked` takes and releases its own lock, and
        // `switched` was assembled inside the hold.
        //
        // ONLY ON THE QUEUE ROAD, and this is §284's one deliberate
        // asymmetry in the event stream. `job.failed` is the announcement
        // that a job has just failed, and on the parked road it failed
        // hours ago - `park_gen` emitted it then, and every subscriber
        // acted on it then. Emitting it again would tell an *arr, a
        // webhook and the dashboard's own failure alarm that a record
        // they have already handled has failed a second time. What DID
        // just happen is the switch, so that is the one that is said.
        if was_queued {
            self.life_emit_parked(&orig);
        }
        self.life_emit("job.switched", switched);
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
///
/// THREE producers stamp the fields this reads, one per road by which a
/// release the user did not click can start downloading:
/// `daemon_park::promote_held_alternative` (a held spare promoted
/// automatically), [`Daemon::alt_switch`] (item 12's offer, clicked),
/// and `hunt::Daemon::stamp_hunt_switch` (section C's search). A fourth
/// road would have to stamp them too, or it renders no clause at all -
/// which is what section C did until 24 Aug 2026, because it lands its
/// replacement on a worker thread rather than inside `park_gen` and so
/// shared none of the code the first two do.
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
