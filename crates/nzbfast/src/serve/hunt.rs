//! §282 section C: hunt for a replacement when a job cannot complete
//! and nothing is held against it.
//!
//! The ordinary answer to a terminal verdict is the M14f promote path in
//! `daemon_park`: a spare is already on the queue, paused at priority
//! -3 with `held_for` set, and promoting it costs one field write. This
//! module is the other case, which is today the COMMON one - nothing
//! was held, the job is dead, and the only thing that can still deliver
//! the release is a copy we have not looked for yet.
//!
//! Item 6's admission test is NOT reimplemented here: `spare::admits`
//! is section B's, it answers exactly this question, and two spellings
//! of one rule is how the two halves of §282 would drift apart. The one
//! thing this caller decides for itself is what an UNCOMPARABLE pair
//! means, and it says `false` - an NZB neither side can read is not a
//! licence to spend a whole download.
//!
//! Four rules shape everything below, and each one is load bearing.
//!
//! 1. **The trigger is a TERMINAL VERDICT, never slowness.** Slowness is
//!    the line or the provider (§275, and the whyslow surface), and
//!    switching on it restarts a download that was going to finish.
//!    Nothing here reads a rate.
//! 2. **NEVER hunt for an *arr-origin job** (item 9). Sonarr and Radarr
//!    own the retry for grabs they sent: they blocklist the release and
//!    re-search. Two agents hunting one episode gives double grabs and a
//!    queue full of alternates - which is the same ownership question
//!    `giveup.rs` reasons about when it decides which instance may be
//!    touched. Report the failure and stand down.
//! 3. **Ride the age gate** (item 10). A post younger than
//!    [`crate::diag::GONE_MIN_AGE_DAYS`] that 430s everywhere is very
//!    likely still PROPAGATING, and every alternate a hunt finds is the
//!    same fresh post - so a hunt below the gate spends a second full
//!    download to reach the identical verdict. Below the gate the answer
//!    is wait and retry, which is what `auto_retry_eligible` already
//!    does.
//! 4. **A replacement that is the same post is worse than useless**
//!    (item 6's admission test). Two indexer results for one release are
//!    very often the same articles re-indexed; such a copy fails
//!    identically AND burns a copy of the budget, so the message-id sets
//!    are compared before anything is enqueued.
//!
//! The whole feature is OFF by default and there is no way to switch it
//! on from Settings yet: the keys are §282 item 13 and are a separate
//! piece of work. [`HuntPolicy`] is the seam they will fill.

use super::giveup::target_keys;
use super::*;

use crate::wall::{Kind, Parsed};
use std::collections::BTreeSet;

/// The cost and consent ceilings a hunt runs under, read off §282 item
/// 13's settings (`altcand::AltSettings`).
///
/// A snapshot rather than three loads scattered through the walk: a
/// hunt decides several things off these and the user may be editing
/// them from Settings while it runs, so every step of one decision
/// should see one set of values.
///
/// `alt_max_copies` and `alt_max_extra_bytes` are SHARED with the
/// held-spare half - item 13 calls them "how many copies of one release
/// this whole mechanism may spend" and "bytes an alternate may add" -
/// which is what stops a target being given two budgets by being
/// pursued down two roads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct HuntPolicy {
    /// `alt_auto_search`. OFF: a hunt spends the user's bytes on a copy
    /// they did not click, so it is opt-in like every other automation
    /// that talks to the outside world on its own initiative.
    pub enabled: bool,
    /// `alt_max_copies`: the most DISTINCT releases that may be
    /// downloaded for one target, the original included. At the default
    /// 2 that is the copy the user asked for plus one replacement.
    ///
    /// Counted off the §96.3 breaker's own distinct-stem list rather
    /// than a second ledger, so it survives a restart and so a retry of
    /// the same dead release is one copy and not two.
    pub max_copies: u32,
    /// `alt_max_extra_bytes`: the most bytes a hunt may add for one
    /// target, on top of whatever the original spent. 0 = unlimited,
    /// which is only ever honoured on a flat-rate install - see
    /// [`NoHunt::MeteredNoBudget`].
    pub max_extra_bytes: u64,
}

impl Default for HuntPolicy {
    fn default() -> Self {
        HuntPolicy {
            enabled: false,
            max_copies: 2,
            max_extra_bytes: 0,
        }
    }
}

/// The work queue `park` writes into and `hunt_tick` drains.
///
/// The three ceilings are NOT here: they are §282 item 13's settings and
/// live on `Daemon::alt` with the held-spare half's, because a cost
/// ceiling that each road keeps its own copy of is two budgets wearing
/// one name. All this owns is the queue and its wake.
#[derive(Debug, Default)]
pub(super) struct HuntState {
    /// Terminal verdicts waiting for the worker. `park` owns the
    /// queue's critical path and a search is two network round trips,
    /// so nothing here happens on park's thread.
    pub q: Mutex<std::collections::VecDeque<HuntRequest>>,
    pub wake: tokio::sync::Notify,
}

/// Why a hunt did not happen. Every arm is a sentence in the log, and
/// most of them are a test - these are the refusals the feature is made
/// of, not error handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum NoHunt {
    /// Item 9. First, and deliberately ahead of even the enabled check,
    /// so no reordering of the gates below can ever let an *arr job
    /// through: the answer for those is the same whatever else is true.
    ArrOwned,
    Disabled,
    /// A full disk, a permission error, a crashed unpack. The post is
    /// fine and a second copy fails the same way - the same gate
    /// `giveup_note_outcome` applies for the same reason.
    LocalFault,
    /// Item 10: the post may still be propagating, or the loss is
    /// ambiguous enough that a journal-resume retry can still heal it.
    StillPropagating,
    /// The name carries no identity a hunt could match on, so a search
    /// would be free to wander onto a different release.
    NoIdentity,
    /// The §96.3 breaker has already given this target up.
    GivenUp,
    /// Item 11: `alt_max_copies` distinct releases have now failed.
    CopyCap(u32),
    /// Item 11: at least one enabled server is a block account and the
    /// byte ceiling is "unlimited". A hunt that drains a metered account
    /// is the failure mode that would make this a liability rather than
    /// a feature, so 0 stops meaning unlimited the moment paid bytes are
    /// in play.
    MeteredNoBudget,
    /// Item 11: the bytes already spent hunting this target, plus the
    /// cheapest surviving candidate, exceed `alt_max_extra_bytes`.
    ByteCap,
    /// Nothing was offered that is the same release and not the same
    /// post.
    NoCandidate,
}

impl NoHunt {
    /// The clause the log line ends with. House voice: no dashes as
    /// punctuation, and it says what happened rather than naming a
    /// variant.
    pub(super) fn why(&self) -> String {
        match self {
            NoHunt::ArrOwned => {
                "the *arr that sent it owns the retry, so nothing was searched for".into()
            }
            NoHunt::Disabled => "automatic replacement search is off".into(),
            NoHunt::LocalFault => {
                "the failure was on this machine, not in the post, so another copy would fail \
                 the same way"
                    .into()
            }
            NoHunt::StillPropagating => format!(
                "the post is under {} days old (or its loss is not proven), so waiting is more \
                 likely to help than another copy",
                crate::diag::GONE_MIN_AGE_DAYS
            ),
            NoHunt::NoIdentity => {
                "the release name carries no identity a search could match safely".into()
            }
            NoHunt::GivenUp => "this target has already been given up".into(),
            NoHunt::CopyCap(n) => {
                format!("{n} copies of this have already failed, which is the configured ceiling")
            }
            NoHunt::MeteredNoBudget => {
                "one of your servers is a block account and no byte ceiling is set, so no paid \
                 bytes were spent"
                    .into()
            }
            NoHunt::ByteCap => "the byte ceiling for this title is already spent".into(),
            NoHunt::NoCandidate => {
                "nothing was offered that is the same release and a different post".into()
            }
        }
    }
}

/// One job's terminal verdict, snapshotted at park time and handed to
/// the worker.
///
/// A snapshot rather than the `Arc<Mutex<Job>>` on purpose: by the time
/// the worker runs, the record has been filed into history and may have
/// been retried, deleted or rewritten. Everything the decision turns on
/// is fixed at the moment of failure, so freezing it is both cheaper and
/// more correct than re-reading a record that has moved on.
#[derive(Debug, Clone)]
pub(super) struct HuntRequest {
    pub nzo_id: String,
    pub name: String,
    pub origin: String,
    pub fail_message: String,
    /// The spooled .nzb of the job that failed. Survives park (the retry
    /// path reads it back), and it is where both the post's age and its
    /// message-id set come from.
    pub nzb_path: PathBuf,
    pub category: String,
}

/// Origin recorded on a job the hunt enqueued: `hunt:<target key>`.
///
/// The `prefix:detail` shape `arr:<client>`, `rss:<feed>` and
/// `watchlist:<slot>|…` already use, so this needs no new `Job` field,
/// no queue.json migration and no history rewrite. The detail is the
/// target key rather than the failed job's id because the accounting
/// this feeds is per TARGET: which episode the bytes went on, not which
/// attempt.
pub(super) fn hunt_origin(target: &str) -> String {
    format!("hunt:{target}")
}

/// The target key a hunt-origin job was grabbed for, or `None`.
pub(super) fn hunt_target(origin: &str) -> Option<&str> {
    origin.strip_prefix("hunt:").filter(|k| !k.is_empty())
}

/// How many candidates a single hunt will fetch and test before giving
/// up. Each fetch is an indexer grab against the user's daily
/// allowance, so this is a cost ceiling and not a search-quality dial.
const MAX_CANDIDATE_FETCHES: usize = 4;

/// Terminal verdicts that may be waiting for the worker at once.
const HUNT_QUEUE_MAX: usize = 64;

/// May this candidate's advertised size be spent under `budget`?
///
/// A size of 0 is UNKNOWN, not free: `parse_results` reports 0 when the
/// indexer sent neither an enclosure length nor a size attribute. While
/// a ceiling is in force an unknown size is refused, because a ceiling
/// that cannot bound what it is about to spend is not a ceiling, and the
/// install this matters on is the one paying by the byte. With no
/// ceiling (flat rate, item 11) an unknown size is ordinary.
pub(super) fn affordable(size: u64, budget: Option<u64>) -> bool {
    match budget {
        None => true,
        Some(b) => size > 0 && size <= b,
    }
}

/// How old the post is in days, from the two places that can know.
///
/// The failure MESSAGE first, because that is the figure the census
/// actually measured off the articles it fetched, and it is the same
/// clause `diag::post_age_from_message` reads for the retry gate. The
/// spooled NZB second, because a repair verdict never carries that
/// clause and the incident §282 is written against is exactly a repair
/// verdict - two 644-day-old posts whose recovery sets could not be
/// obtained.
///
/// `None` means unknown, and unknown does NOT hunt. That is the opposite
/// of the direction the auto-retry gate takes with the same figure, and
/// deliberately so: the cost of a wrong retry is one duplicate download
/// of a post we already have most of, where the cost of a wrong hunt is
/// a whole extra release, possibly on paid bytes.
pub(super) fn post_age_days(fail_message: &str, nzb_path: &Path, now: i64) -> Option<u32> {
    if let Some(d) = crate::diag::post_age_from_message(fail_message) {
        return Some(d);
    }
    let bytes = std::fs::read(nzb_path).ok()?;
    let nzb = nzbkit::nzb::Nzb::parse(&bytes).ok()?;
    // NEWEST, matching `post_year_of`: a repost or a fill tops an old
    // NZB up with recent articles, and it is the most recent posting
    // that bounds how long propagation has had.
    let newest = nzb.files.iter().map(|f| f.date).max().unwrap_or(0);
    if newest <= 0 || now <= newest {
        return None;
    }
    Some(((now - newest) / 86_400) as u32)
}

/// Item 10, as one predicate.
///
/// A missing-articles verdict goes through `missing_articles_proven_stale`
/// rather than the raw age, because that function carries four
/// exclusions the age alone cannot see: a loss to transport errors, to a
/// server that never connected, to damaged rather than absent articles,
/// or to a retention mask is OURS to fix, and a journal-resume retry
/// heals it. Hunting on one of those spends a whole extra release on a
/// fault that was never in the post.
///
/// Every other post-unavailability verdict (a repair that could not
/// complete, a recovery set that could not be fetched) carries no such
/// clause, so it is judged on the age alone.
fn age_gate_open(fail_message: &str, nzb_path: &Path, now: i64) -> bool {
    if fail_kind(fail_message) == crate::failkind::FailKind::MissingArticles {
        return crate::diag::missing_articles_proven_stale(fail_message);
    }
    post_age_days(fail_message, nzb_path, now).is_some_and(|d| d >= crate::diag::GONE_MIN_AGE_DAYS)
}

/// The gates that need no network and no store, in the order their
/// answers matter. Split out from [`Daemon::hunt_one`] so item 9 and
/// item 10 can be pinned without standing a daemon up.
///
/// Returns the target keys the hunt would run against, which is what
/// every later step is accounted against.
pub(super) fn hunt_gates(
    req: &HuntRequest,
    policy: HuntPolicy,
    now: i64,
) -> Result<(Parsed, Vec<String>), NoHunt> {
    // ITEM 9, FIRST AND UNCONDITIONALLY. Nothing below may run for a job
    // an *arr sent us, whatever the settings say, so this test is ahead
    // of the enabled check rather than tucked in among the others. A
    // later refactor that reorders the rest cannot reach past it, and
    // `an_arr_origin_job_is_never_hunted_for` pins that it is still
    // first.
    if is_arr_origin(&req.origin) {
        return Err(NoHunt::ArrOwned);
    }
    if !policy.enabled {
        return Err(NoHunt::Disabled);
    }
    if !fail_kind(&req.fail_message).post_unavailable() {
        return Err(NoHunt::LocalFault);
    }
    if !age_gate_open(&req.fail_message, &req.nzb_path, now) {
        return Err(NoHunt::StillPropagating);
    }
    let p = crate::wall::parse_release(&req.name);
    let keys = target_keys(&p);
    // Both, never one. `target_keys` names the episode or the film, and
    // is what the cost accounting and the breaker key on; `dupe_key` is
    // the release identity a candidate has to meet. A name that answers
    // neither is one a search cannot be aimed with, and aiming it anyway
    // is how a hunt wanders onto a different release.
    if keys.is_empty() || dupe_key(&req.name).is_none() {
        return Err(NoHunt::NoIdentity);
    }
    Ok((p, keys))
}

/// Is this candidate the same RELEASE as the job that failed?
///
/// Identity is `Parsed` plus dupe-key, both: the dupe key says "the same
/// episode of the same show, whatever the encode", and the target keys
/// say the parse agrees about which episode that is. A candidate that
/// meets only one of them is a different release wearing a similar name.
fn same_release(candidate: &str, want_dupe: &str, want_keys: &[String]) -> bool {
    if dupe_key(candidate).as_deref() != Some(want_dupe) {
        return false;
    }
    let ck = target_keys(&crate::wall::parse_release(candidate));
    !ck.is_empty() && ck.iter().any(|k| want_keys.contains(k))
}

/// One candidate replacement, from whichever source offered it.
struct Cand {
    stem: String,
    rank: u32,
    posted: i64,
    size: u64,
    src: CandSrc,
}

enum CandSrc {
    /// Our own index can synthesise the NZB, so this costs no indexer
    /// budget at all and is tried first.
    #[cfg(feature = "indexer")]
    Local(i64),
    External {
        url: String,
        indexer: String,
        origin: SourceOrigin,
    },
}

impl Daemon {
    /// The ceilings a hunt runs under right now.
    ///
    /// Read through one function so §282 item 13 has one place to make
    /// the three keys writable, and so nothing downstream has to know
    /// they are atomics.
    pub(in crate::serve) fn hunt_policy(&self) -> HuntPolicy {
        HuntPolicy {
            enabled: self.alt.auto_search.load(Ordering::Relaxed),
            // 0 is not a legal ceiling, it is an unset one - a cap of
            // zero refuses every hunt including the first, which reads
            // exactly like the feature being broken rather than off.
            // `AltSettings` defaults it to 2; this is the guard for a
            // settings write that clears it.
            max_copies: match self.alt.max_copies.load(Ordering::Relaxed).min(64) {
                0 => HuntPolicy::default().max_copies,
                n => n,
            },
            max_extra_bytes: self.alt.max_extra_bytes.load(Ordering::Relaxed),
        }
    }

    /// §282 item 8: a job has failed for good and nothing was held
    /// against it, so ask the worker to look for a replacement.
    ///
    /// Called from `park_gen`, which owns no locks by then and must not
    /// block: a search is two network round trips and an NZB fetch. So
    /// this only snapshots and queues, and it does the two cheapest
    /// refusals inline - the *arr rule, so no *arr job is ever even
    /// written into the queue this worker drains, and the enabled check,
    /// so an install with the feature off pays one relaxed load per
    /// failure and nothing else.
    pub(in crate::serve) fn hunt_request(&self, job: &Arc<Mutex<Job>>) {
        // Before the snapshot, so an install that has not opted in pays
        // one relaxed load per failure and no allocation at all.
        if !self.alt.auto_search.load(Ordering::Relaxed) {
            return;
        }
        let req = {
            let g = job.lock_ok();
            // Item 9's first of two gates, taken under the job lock we
            // are already holding. The second is at the top of
            // `hunt_gates`, and both are tested: one gate is a gate a
            // refactor can delete without anything going red.
            if is_arr_origin(&g.origin) {
                return;
            }
            HuntRequest {
                nzo_id: g.nzo_id.clone(),
                name: g.name.clone(),
                origin: g.origin.clone(),
                fail_message: g.fail_message.clone(),
                nzb_path: g.nzb_path.clone(),
                category: g.category.clone(),
            }
        };
        let mut q = self.hunt.q.lock_ok();
        // Bounded, because park is faster than a search: a queue of
        // failing jobs would otherwise grow this without limit while the
        // worker is out on a 15 s indexer call. Dropping the NEWEST is
        // the right end to drop - the ones already queued have waited
        // longer, and a storm this size is one the copy caps are about
        // to refuse anyway.
        if q.len() >= HUNT_QUEUE_MAX {
            warn!(
                target: "queue",
                "{}: {HUNT_QUEUE_MAX} replacement searches are already waiting,                  so no search was queued for this one",
                req.nzo_id
            );
            return;
        }
        q.push_back(req);
        drop(q);
        self.hunt.wake.notify_one();
    }

    /// Drain everything queued. Runs on a blocking thread: the search,
    /// the NZB fetch and the enqueue are all synchronous.
    pub(in crate::serve) fn hunt_tick(&self) {
        loop {
            let Some(req) = self.hunt.q.lock_ok().pop_front() else {
                return;
            };
            if let Err(no) = self.hunt_one(&req) {
                info!(
                    target: "queue",
                    "{}: no replacement searched for ({}): {}",
                    req.nzo_id, req.name, no.why()
                );
            }
        }
    }

    /// One request, from the gates through to an enqueued replacement.
    fn hunt_one(&self, req: &HuntRequest) -> Result<(), NoHunt> {
        let policy = self.hunt_policy();
        let now = unix_now();
        let (p, keys) = hunt_gates(req, policy, now)?;
        let threshold = self.arr_giveup_threshold.load(Ordering::Relaxed).min(1000) as u32;

        // ITEM 11, first half: the §96.3 breaker. A target it has already
        // given up is one three or more distinct releases have failed
        // for, and that is precisely the content a hunt would loop on
        // forever.
        if self.giveup.lock_ok().tripped(&p, threshold) {
            return Err(NoHunt::GivenUp);
        }
        // ...and the hunt COUNTS against it. Recorded here rather than
        // in `giveup_note_outcome`, which sees only the two automated
        // grab paths and returns early for a job the user added by hand
        // - which is most of what this feature exists for. The store
        // dedups by stem, so a target the watchlist already recorded is
        // not counted twice, and a retry of one dead release is one
        // piece of evidence and not two.
        //
        // Worth saying plainly: this makes hunted copies visible to the
        // breaker's other readers, so enough of them can trip a target
        // the watchlist is also pursuing. That is the intent - the
        // counter means "distinct releases of this target that finally
        // failed", and a hunted copy is one - and it can only happen on
        // an install that has opted the hunt in.
        let copies = {
            let mut st = self.giveup.lock_ok();
            st.record_failure(&keys, &req.name, now) as u32
        };
        self.save_giveup();
        if copies >= policy.max_copies {
            return Err(NoHunt::CopyCap(copies));
        }

        // ITEM 11, second half: the byte ceiling, and the one rule in it
        // that is not a number. `may_spend_on_measurement` is the shared
        // predicate for "may nzbfast spend this server's bytes on its
        // own curiosity", and a copy the user did not click is exactly
        // that. On an install where any enabled server answers no, an
        // "unlimited" ceiling is refused outright rather than honoured.
        let budget = self.hunt_budget(&keys, policy)?;

        let mut cands = self.hunt_candidates(req, &p, &keys);
        // Best first, the way the M14f promote path ranks its held
        // spares, so "best" means one thing in both places. Newest post
        // breaks a tie: of two equal encodes the more recent one has had
        // less of its retention window spent.
        cands.sort_by(|a, b| b.rank.cmp(&a.rank).then_with(|| b.posted.cmp(&a.posted)));

        // Refused BEFORE the fetch ceiling below, not inside the loop:
        // an over-budget candidate that ate one of the four attempts
        // would let a couple of expensive results starve the affordable
        // ones behind them.
        //
        // A size of 0 is UNKNOWN, not free - `parse_results` reports 0
        // when the indexer sent neither an enclosure length nor a size
        // attribute. While a ceiling is in force an unknown size is
        // refused, because a ceiling that cannot bound what it is
        // spending is not a ceiling, and the install this matters on is
        // the one paying by the byte.
        let before = cands.len();
        cands.retain(|c| affordable(c.size, budget));
        let any_over_budget = cands.len() != before;

        let want = std::fs::read(&req.nzb_path)
            .ok()
            .and_then(|b| nzbkit::nzb::Nzb::parse(&b).ok())
            .map(|n| spare::post_ids(&n));
        for cand in cands.into_iter().take(MAX_CANDIDATE_FETCHES) {
            let Some(bytes) = self.hunt_fetch(&cand) else {
                continue;
            };
            // ITEM 6's admission test, and it is `spare`'s rather than a
            // second copy of it: a candidate that is the same post fails
            // identically, so refusing it here is what keeps the copy
            // budget for a copy that might work.
            //
            // `unknown = false`, which is the ADMISSION side of that
            // function's argument and not the promotion side. A spare
            // that cannot be compared is already on the queue and the
            // user can see it; a hunt candidate is a whole download this
            // daemon is about to start on its own initiative, so a pair
            // it cannot compare is refused rather than waved through.
            let got = nzbkit::nzb::Nzb::parse(&bytes.0).ok();
            let admitted = match (want.as_ref(), got.as_ref()) {
                (Some(w), Some(g)) => spare::admits(w, &spare::post_ids(g), false),
                _ => false,
            };
            if !admitted {
                info!(
                    target: "queue",
                    "{}: {} was not queued as a replacement - it is the same post as the \
                     job that failed (or neither NZB could be read), so it would fail the \
                     same way",
                    req.nzo_id, cand.stem
                );
                continue;
            }
            if self.hunt_enqueue(req, &cand, bytes, &keys) {
                return Ok(());
            }
        }
        if any_over_budget {
            return Err(NoHunt::ByteCap);
        }
        Err(NoHunt::NoCandidate)
    }

    /// How many further bytes this target may cost, or `None` for no
    /// ceiling. `Err` when a ceiling is REQUIRED and none is set.
    fn hunt_budget(&self, keys: &[String], policy: HuntPolicy) -> Result<Option<u64>, NoHunt> {
        if policy.max_extra_bytes == 0 {
            return if self.hunt_metered() {
                Err(NoHunt::MeteredNoBudget)
            } else {
                Ok(None)
            };
        }
        let spent = self.hunt_spent(keys);
        if spent >= policy.max_extra_bytes {
            return Err(NoHunt::ByteCap);
        }
        Ok(Some(policy.max_extra_bytes - spent))
    }

    /// Does any enabled server bill for its bytes?
    ///
    /// `may_spend_on_measurement` rather than a fresh reading of the
    /// config, because the callers have to AGREE about what counts as a
    /// metered account: it honours both the explicit `block_account`
    /// flag and the older inference from a configured prepaid block,
    /// which plenty of installs still rely on.
    fn hunt_metered(&self) -> bool {
        nzbkit::config::Config::load(&self.cfg_path)
            .map(|c| {
                c.servers
                    .iter()
                    .any(|s| s.enabled && !s.may_spend_on_measurement())
            })
            .unwrap_or(false)
    }

    /// Bytes already spent hunting these targets, across the queue and
    /// history.
    ///
    /// Read off the ORIGIN rather than a ledger of its own: a hunted job
    /// records `hunt:<target key>`, both stores are already persisted,
    /// and a job the user deleted took its bytes off the account's
    /// future as surely as it spent them, so counting only what is still
    /// on record is the reading that cannot over-refuse.
    fn hunt_spent(&self, keys: &[String]) -> u64 {
        let mine = |g: &Job| -> u64 {
            match hunt_target(&g.origin) {
                Some(k) if keys.iter().any(|w| w == k) => g.downloaded_bytes,
                _ => 0,
            }
        };
        let q: u64 = self
            .queue
            .lock_ok()
            .iter()
            .map(|j| mine(&j.lock_ok()))
            .sum();
        let h: u64 = self
            .history
            .lock_ok()
            .iter()
            .map(|j| mine(&j.lock_ok()))
            .sum();
        q.saturating_add(h)
    }

    /// Everything that might replace this release, from our own index
    /// and from every enabled indexer, already filtered to the same
    /// release and to stems that have not failed for this target before.
    fn hunt_candidates(&self, req: &HuntRequest, p: &Parsed, keys: &[String]) -> Vec<Cand> {
        let want_dupe = dupe_key(&req.name).unwrap_or_default();
        // Stems already proven dead for this target. Cheap, and it saves
        // an indexer grab per copy we have already buried.
        let dead: BTreeSet<String> = {
            let st = self.giveup.lock_ok();
            keys.iter()
                .filter_map(|k| st.targets.get(k))
                .flat_map(|t| t.stems.iter().cloned())
                .collect()
        };
        let keep = |stem: &str| !dead.contains(stem) && same_release(stem, &want_dupe, keys);
        let mut out = Vec::new();

        // Our own index first: it synthesises the NZB locally, so it
        // spends no indexer allowance and cannot be rate limited.
        #[cfg(feature = "indexer")]
        {
            let hits = self
                .with_index_read(|ix| ix.search(&p.title, 500).ok())
                .unwrap_or_default();
            for r in hits.iter().filter(|r| r.complete) {
                let stem = r.display_name().to_string();
                if !keep(&stem) {
                    continue;
                }
                out.push(Cand {
                    rank: crate::watchlist::quality_rank(&crate::wall::parse_release(&stem)),
                    posted: r.first_posted,
                    size: r.total_bytes,
                    stem,
                    src: CandSrc::Local(r.id),
                });
            }
        }

        for c in self.hunt_search_external(p) {
            if !keep(&c.title) {
                continue;
            }
            out.push(Cand {
                rank: crate::watchlist::quality_rank(&crate::wall::parse_release(&c.title)),
                posted: c.posted,
                size: c.size,
                stem: c.title,
                src: CandSrc::External {
                    url: c.link,
                    indexer: c.indexer,
                    origin: c.origin,
                },
            });
        }
        out
    }
}

/// One external search result, tagged with the indexer that offered it.
///
/// Its own type rather than watchlist's `ExtCand` because that one is
/// built from a `WatchItem` and carries the fields a watchlist decision
/// wants; the two searches share `indexer_search_one` underneath, which
/// is the part that must not be duplicated.
struct HuntExt {
    title: String,
    link: String,
    size: u64,
    posted: i64,
    indexer: String,
    origin: SourceOrigin,
}

impl Daemon {
    /// Ask every enabled, in-budget indexer about this release.
    ///
    /// Free text on the parsed title plus the episode or year, which is
    /// what a scene name carries anyway, and the results are filtered on
    /// `same_release` afterwards - so a loose query costs nothing but a
    /// few discarded rows, where a query too tight to match a different
    /// group's encode costs the whole feature.
    fn hunt_search_external(&self, p: &Parsed) -> Vec<HuntExt> {
        let list: Vec<crate::newznab::IndexerConfig> = self
            .indexers
            .lock_ok()
            .iter()
            .filter(|i| i.enabled)
            .cloned()
            .collect();
        if list.is_empty() {
            return Vec::new();
        }
        let mut runnable = Vec::new();
        {
            let mut rt = self.indexer_rt.lock_ok();
            rt.usage.roll(unix_now());
            let now = std::time::Instant::now();
            for i in list {
                if rt.penalty_until.get(&i.name).is_some_and(|t| *t > now) {
                    continue;
                }
                if !rt.usage.hit_allowed(&i) {
                    continue;
                }
                rt.usage.count_hit(&i.name);
                runnable.push(i);
            }
        }
        if runnable.is_empty() {
            return Vec::new();
        }
        save_indexer_usage(self);
        let q = match (p.season, p.episode, p.year) {
            (Some(s), Some(e), _) => format!("{} S{s:02}E{e:02}", p.title),
            (Some(s), None, _) => format!("{} S{s:02}", p.title),
            (None, None, Some(y)) => format!("{} {y}", p.title),
            _ => p.title.clone(),
        };
        let query = crate::newznab::SearchQuery {
            q,
            cats: match p.kind {
                Kind::Movie => vec![2000],
                Kind::Tv => vec![5000],
                _ => Vec::new(),
            },
            limit: 100,
            ..Default::default()
        };
        // The worker is already off the queue's critical path, so a
        // plain scoped fan-out is fine; each call carries the shared
        // agent's 15 s ceiling.
        let results: Vec<_> = std::thread::scope(|s| {
            let handles: Vec<_> = runnable
                .iter()
                .map(|i| {
                    let query = query.clone();
                    s.spawn(move || (i.name.clone(), indexer_search_one(i, &query)))
                })
                .collect();
            handles.into_iter().filter_map(|h| h.join().ok()).collect()
        });
        let mut out = Vec::new();
        for (name, r) in results {
            match r {
                Ok((items, origin)) => {
                    for it in items {
                        out.push(HuntExt {
                            title: it.title,
                            link: it.link,
                            size: it.size,
                            posted: it.posted,
                            indexer: name.clone(),
                            origin: origin.clone(),
                        });
                    }
                }
                Err(e) => {
                    if matches!(e, crate::newznab::NewznabError::Limit(..)) {
                        self.indexer_rt.lock_ok().penalty_until.insert(
                            name.clone(),
                            std::time::Instant::now() + INDEXER_LIMIT_BACKOFF,
                        );
                    }
                    warn!(target: "queue", "hunt: {name}: {e}");
                }
            }
        }
        out
    }

    /// The candidate's NZB bytes, and the response headers when it came
    /// over HTTP. `None` when it could not be had, which is never fatal:
    /// the caller moves to the next candidate.
    fn hunt_fetch(&self, cand: &Cand) -> Option<(Vec<u8>, Option<Fetched>)> {
        match &cand.src {
            #[cfg(feature = "indexer")]
            CandSrc::Local(id) => {
                let xml = self.with_index_read(|ix| ix.make_nzb(*id).ok())?;
                Some((xml.into_bytes(), None))
            }
            CandSrc::External {
                url,
                indexer,
                origin,
            } => {
                // The search snapshotted the enabled indexers and then
                // awaited the network. By the time we get here the user
                // may have disabled or deleted that account, and a
                // MISSING config is not a budget question - it is a
                // revoked credential we must not spend (the same trap
                // the watchlist grab documents).
                {
                    let mut rt = self.indexer_rt.lock_ok();
                    rt.usage.roll(unix_now());
                    let cfg = self
                        .indexers
                        .lock_ok()
                        .iter()
                        .find(|i| &i.name == indexer)
                        .cloned();
                    let cfg = cfg.filter(|c| c.enabled)?;
                    if !rt.usage.grab_allowed(&cfg) {
                        warn!(
                            target: "queue",
                            "hunt: {indexer}: daily grab budget reached, {} not fetched",
                            cand.stem
                        );
                        return None;
                    }
                }
                // fetch_url_from: the link is an `<enclosure url>` this
                // indexer's own response chose, so it may not reach a
                // private address the indexer does not own (M12).
                match fetch_url_from(url, origin) {
                    Ok(f) => {
                        self.indexer_rt.lock_ok().usage.count_grab(indexer);
                        save_indexer_usage(self);
                        Some((f.bytes.clone(), Some(f)))
                    }
                    Err(e) => {
                        // The URL carries the user's apikey, and logtee
                        // mirrors this into the dashboard log.
                        warn!(
                            target: "queue",
                            "hunt: fetching {} from {indexer}: {}",
                            cand.stem,
                            redact_url_creds(&e.to_string())
                        );
                        None
                    }
                }
            }
        }
    }

    /// Put the surviving candidate on the queue, runnable, and say so.
    ///
    /// `allow_dupe`: the replacement IS a duplicate of the release that
    /// just failed, and that is the whole point - without it the M14f
    /// hold would park the only copy that can still deliver.
    fn hunt_enqueue(
        &self,
        req: &HuntRequest,
        cand: &Cand,
        fetched: (Vec<u8>, Option<Fetched>),
        keys: &[String],
    ) -> bool {
        let origin = hunt_origin(&keys[0]);
        let (bytes, headers) = fetched;
        let out = match headers {
            Some(f) => self.enqueue_fetched(
                &f,
                &cand.stem,
                &req.category,
                0,
                None,
                None,
                0,
                &origin,
                true,
            ),
            None => self.enqueue(
                &bytes,
                &cand.stem,
                &req.category,
                0,
                None,
                None,
                &origin,
                true,
            ),
        };
        match out {
            Ok(e) => {
                info!(
                    target: "queue",
                    "{}: {} could not complete, so {} was queued in its place ({})",
                    e.nzo_id, req.name, cand.stem, origin
                );
                // §282 item 14 will want this in the report and the
                // history row too; the event ring is what an open
                // dashboard toasts off, so the switch is visible the
                // moment it happens rather than only in the log.
                self.life_emit(
                    "job.replaced",
                    json!({
                        "nzo_id": e.nzo_id,
                        "failed_nzo_id": req.nzo_id,
                        "failed_name": req.name,
                        "name": cand.stem,
                        "target": keys[0],
                    }),
                );
                true
            }
            Err(e) => {
                warn!(target: "queue", "hunt: enqueue {}: {e}", cand.stem);
                false
            }
        }
    }
}

#[cfg(test)]
#[path = "hunt_tests.rs"]
mod hunt_tests;
