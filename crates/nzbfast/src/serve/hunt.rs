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
//! The whole feature is OFF by default, and it IS switchable from
//! Settings - `alt_auto_search`, beside `alt_max_copies` and
//! `alt_max_extra_bytes`, read through [`Daemon::hunt_policy`].
//!
//! This paragraph claimed the opposite until 24 Aug 2026 ("no way to
//! switch it on from Settings yet: the keys are §282 item 13 and are a
//! separate piece of work"), and it was never true: item 13's keys
//! landed in `c1c30adab` at 11:54, 48 minutes BEFORE this file did, so
//! the header was written against a tree that had already moved. The
//! merge that pointed the code at the real settings (`bcd67456d`)
//! rewired `hunt_policy` and left the header alone. Worth the space
//! because of what a lie in this position costs: it reads as a standing
//! invitation to go and build the settings keys, and §282 section C is
//! already the part of this backlog that got BUILT TWICE by two lanes
//! in one afternoon.
//!
//! ## Two entry points, and only one of them is the daemon's initiative
//!
//! §282 item 20 added the second one. [`Daemon::hunt_request`] is the
//! AUTOMATIC road: a job has failed for good, nothing was held, and the
//! daemon decides on its own to go looking. [`Daemon::hunt_offer`] and
//! [`Daemon::hunt_pick`] are the CLICKED road: a person is looking at a
//! queue row that `altcand::terminal_reason` says cannot finish, and has
//! asked for a search. The pick list is [`Daemon::hunt_candidates`] with
//! the enqueue withheld, so both roads rank, filter and admit by exactly
//! the same rules; [`Trigger`] carries the difference, which is two
//! refusals wide and no wider.

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

/// What asked for a hunt: the daemon's own conclusion, or a person.
///
/// §282 item 20 gave this module a second entry point, and it is NOT the
/// same act as the first. `Auto` is the daemon spending the user's bytes
/// on its own initiative after a job has died. `Clicked` is a person
/// looking at a doomed queue row and asking for a search.
///
/// **It changes exactly two of the refusals below, and it is written as
/// a parameter rather than a second walk so that everything it does NOT
/// change stays impossible to diverge.** The *arr rule, the age gate,
/// the identity test, the copy cap, the ranking, item 6's admission test
/// and the same-release filter are the same on both roads.
///
/// The two it changes, and why:
///
/// 1. **`alt_auto_search`** ([`NoHunt::Disabled`]) is the consent for
///    the DAEMON to search. A click is its own consent, given at the
///    moment and about this one release, so requiring the setting as
///    well would make the button dead on every default install - which
///    is the gap item 20 exists to close. §282 item 12 calls the click
///    "the default posture ... safe on any account type", and it is safe
///    for the same reason: nothing happens without it.
/// 2. **The metered guard** ([`NoHunt::MeteredNoBudget`]) refuses an
///    "unlimited" ceiling on an install with a block account, because
///    nobody agreed to spend paid bytes. On a click somebody just did.
///    A ceiling the user actually SET still applies on both roads - that
///    is a number they chose, not a stand-in for consent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Trigger {
    /// `park` concluded the job was dead and nothing was held.
    Auto,
    /// A person pressed the button on the queue row (§282 item 20).
    Clicked,
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
    /// §282 item 20: the last pick list shown per doomed row, so the
    /// PICK does not have to search again.
    ///
    /// A cache and not a ledger. Re-running the search on the pick would
    /// spend a second hit of the user's daily indexer allowance to
    /// re-derive a list they are looking at, and would let the row they
    /// clicked be a different row by the time it is fetched. Losing it -
    /// a restart, an eviction, the age below - costs one honest "search
    /// again", which is why nothing durable is written for it.
    pub offers: Mutex<std::collections::HashMap<String, HuntOffers>>,
}

/// One row's cached pick list.
#[derive(Debug)]
pub(super) struct HuntOffers {
    /// When it was taken, for [`OFFER_TTL_SECS`].
    at: i64,
    cands: Vec<Cand>,
}

/// How long a cached pick list may be picked from. Past it the search
/// is re-run, because an indexer's answer is a statement about right
/// now: a copy on the list may have been taken down since, and the
/// user's own budgets and settings may have moved.
const OFFER_TTL_SECS: i64 = 30 * 60;

/// How many doomed rows may hold a cached pick list at once. Small on
/// purpose: this exists for the row a person is looking at, and the
/// oldest entry is dropped to make room.
const OFFER_ROWS_CACHED: usize = 8;

/// How many candidates the pick list shows. More than
/// [`MAX_CANDIDATE_FETCHES`] because a row on this list costs nothing
/// until it is picked, where the automatic road fetches every candidate
/// it reaches.
const MAX_OFFER_ROWS: usize = 12;

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
                // "spent" and not "failed": since §290 this count is
                // live copies as well as buried ones, which is the
                // whole of F-09's fix - two admissions at zero progress
                // used to see a spend of nothing.
                format!(
                    "{n} copies of this title have already been spent, which is the \
                         configured ceiling"
                )
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
    /// The classification the failure's producer stated, where there was
    /// one - TODO 307 item 1. Carried in the snapshot for the same
    /// reason the message is: the gates below are answered off this
    /// record and not off a job that has since moved on.
    ///
    /// `None` on the QUEUE road, and honestly so: that road synthesises
    /// its sentence from `altcand::terminal_reason` for a job that has
    /// not failed yet, so no producer has classified anything and the
    /// string classifier is the only evidence there is.
    pub fail_code: Option<FailKind>,
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
fn age_gate_open(kind: FailKind, fail_message: &str, nzb_path: &Path, now: i64) -> bool {
    if kind == FailKind::MissingArticles {
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
    trigger: Trigger,
) -> Result<(Parsed, Vec<String>), NoHunt> {
    // ITEM 9, FIRST AND UNCONDITIONALLY. Nothing below may run for a job
    // an *arr sent us, whatever the settings say, so this test is ahead
    // of the enabled check rather than tucked in among the others. A
    // later refactor that reorders the rest cannot reach past it, and
    // `an_arr_origin_job_is_never_hunted_for` pins that it is still
    // first.
    //
    // AND IT HOLDS ON THE CLICKED ROAD TOO (§282 item 20a, which the
    // section leaves open and which is decided HERE). The argument for
    // letting a person through is real: they can see what their *arr is
    // doing and we cannot, and `altcand::alt_switch` already lets them
    // promote a held spare on an *arr row today with no gate at all. It
    // loses to two facts about what the button would actually do.
    //
    // First, a spare is a row the *arr ITSELF pushed - the only *arr
    // rows §282 can promote, because item 5's spares are grabbed from
    // OUR search and an *arr job never has one. A hunt is different in
    // kind: it starts a whole download of a release the *arr never
    // chose and has never heard of, under our own `hunt:<target>`
    // origin and a fresh nzo_id. The *arr blocklists the release it did
    // grab and searches again on its own poll cycle, so the user ends
    // up paying for the episode twice, and the copy we picked is not
    // the one their library is waiting on. That is item 9's harm
    // exactly, and a click does not make it stop being the harm - it
    // only makes it the user's.
    //
    // Second, and this is what settles it rather than merely arguing
    // it: refusing costs NOTHING THAT SHIPS. The button does not exist
    // yet, so the gate takes no capability away from anybody, and
    // loosening it later is this one `if` plus its copy. Turning it on
    // and finding out it double-grabs is a behaviour people have
    // already built habits around. The conservative direction is the
    // reversible one.
    //
    // The row says so rather than going quiet: the drawer draws no
    // search button on an *arr-origin row and names the reason, so the
    // user is told the *arr owns the retry instead of pressing a button
    // that answers with a refusal.
    if is_arr_origin(&req.origin) {
        return Err(NoHunt::ArrOwned);
    }
    // The setting is consent for the DAEMON to search. See [`Trigger`].
    if trigger == Trigger::Auto && !policy.enabled {
        return Err(NoHunt::Disabled);
    }
    // TODO 307 item 1: the producer's own verdict where it stated one,
    // and only then the sentence. Both gates take the SAME kind - asking
    // twice is how one gate ends up answering about a code and the other
    // about the prose.
    let kind = crate::failkind::job_kind(req.fail_code, &req.fail_message);
    if !kind.post_unavailable() {
        return Err(NoHunt::LocalFault);
    }
    if !age_gate_open(kind, &req.fail_message, &req.nzb_path, now) {
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

/// Best first, the way the M14f promote path ranks its held spares, so
/// "best" means one thing in both places. Newest post breaks a tie: of
/// two equal encodes the more recent one has had less of its retention
/// window spent.
///
/// One function because §282 item 20's pick list must be ordered exactly
/// as the automatic road's attempt order is - a user reading a list whose
/// top row is not the one the daemon would have taken is being shown a
/// different feature.
fn sort_best_first(cands: &mut [Cand]) {
    cands.sort_by(|a, b| b.rank.cmp(&a.rank).then_with(|| b.posted.cmp(&a.posted)));
}

/// One candidate replacement, from whichever source offered it.
///
/// `Clone` and `Debug` because §282 item 20 caches the pick list between
/// the search and the click - see [`HuntState::offers`].
#[derive(Debug, Clone)]
struct Cand {
    stem: String,
    rank: u32,
    posted: i64,
    size: u64,
    src: CandSrc,
}

#[derive(Debug, Clone)]
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

impl Cand {
    /// Which indexer offered this, for the pick list. Empty for our own
    /// index, which is not an account name and needs no label.
    fn source(&self) -> &str {
        match &self.src {
            #[cfg(feature = "indexer")]
            CandSrc::Local(_) => "",
            CandSrc::External { indexer, .. } => indexer,
        }
    }

    /// The handle the dashboard hands back to pick this candidate.
    ///
    /// A DIGEST of what identifies the candidate rather than its index
    /// in the list, which is §274's rule for the same reason: a list
    /// re-taken between the render and the click renumbers, and an index
    /// then picks a different release than the one under the cursor. A
    /// name alone will not do either - two indexers offer the same stem
    /// and they are different fetches - so the source is hashed with it.
    ///
    /// Not a security boundary and not persisted: both ends of it are
    /// one process, and a handle that does not resolve is answered with
    /// "search again" rather than with a guess.
    fn key(&self) -> String {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        self.stem.hash(&mut h);
        match &self.src {
            #[cfg(feature = "indexer")]
            CandSrc::Local(id) => {
                0u8.hash(&mut h);
                id.hash(&mut h);
            }
            CandSrc::External { url, indexer, .. } => {
                1u8.hash(&mut h);
                indexer.hash(&mut h);
                url.hash(&mut h);
            }
        }
        format!("{:016x}", h.finish())
    }
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
                fail_code: g.fail_code,
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
        let (p, keys) = hunt_gates(req, policy, now, Trigger::Auto)?;
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
        let budget = self.hunt_budget(&keys, policy, Trigger::Auto)?;

        let mut cands = self.hunt_candidates(req, &p, &keys);
        sort_best_first(&mut cands);

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
        let mut any_over_budget = cands.len() != before;
        // §290 (Codex F-09). The two checks above are the CHEAP ones and
        // they stay: `budget` is historical spend against an indexer's
        // ADVERTISED size, which is what lets an unaffordable candidate
        // be dropped before it eats one of the four fetches. Neither is
        // a ceiling on its own. The advertised figure is the seller's,
        // and the spend is read off rows that may have downloaded
        // nothing yet, so the decision that actually binds is taken
        // below - under `alt_gate`, against the parsed NZB's real size,
        // and released only once the row is published.
        let ctx = self.alt_ctx(&req.nzo_id, &req.name, keys.clone());

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
            // §290: admission and publication under ONE hold of the
            // gate, so a second hunt for this target cannot read a
            // spend this one is about to add to. `total_bytes` off the
            // PARSED NZB, never `cand.size`: an external result that
            // advertises 1 MB and supplies 100 GB walked through a 1 GB
            // ceiling until this line existed (F-09).
            let want = got.as_ref().map(|n| n.total_bytes()).unwrap_or(0);
            let gate = self.alt_gate();
            match self.alt_admit(&ctx, want, Trigger::Auto) {
                Ok(()) => {
                    if self.hunt_enqueue(req, &cand, bytes, &keys) {
                        return Ok(());
                    }
                }
                // The candidate is too big, not the target too spent:
                // a smaller one behind it may still fit, so this is a
                // `continue` and the refusal is only reported if
                // nothing else lands.
                Err(NoHunt::ByteCap) => {
                    drop(gate);
                    info!(
                        target: "queue",
                        "{}: {} was not queued as a replacement - its .nzb is {} bytes, which \
                         is over the byte ceiling left for this title",
                        req.nzo_id, cand.stem, want
                    );
                    any_over_budget = true;
                }
                // A copy ceiling or a metered refusal is about the
                // TARGET, so no other candidate can help.
                Err(e) => return Err(e),
            }
        }
        if any_over_budget {
            return Err(NoHunt::ByteCap);
        }
        Err(NoHunt::NoCandidate)
    }

    /// How many further bytes this target may cost, or `None` for no
    /// ceiling. `Err` when a ceiling is REQUIRED and none is set.
    fn hunt_budget(
        &self,
        keys: &[String],
        policy: HuntPolicy,
        trigger: Trigger,
    ) -> Result<Option<u64>, NoHunt> {
        if policy.max_extra_bytes == 0 {
            // "Unlimited" is refused on a metered install because nobody
            // agreed to spend paid bytes on a copy they did not pick. On
            // a click somebody just did, about this one release, with
            // the row in front of them - so the guard is what it is
            // standing in for, and it stands down. A ceiling the user
            // actually SET is a number they chose and still applies on
            // both roads: it is the arm below, which this never reaches.
            return if trigger == Trigger::Auto && self.hunt_metered() {
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
    /// A config that will not LOAD answers "metered", not "free". This
    /// is the one place the daemon asks whether provider bytes cost
    /// money before spending them on nobody's click, and it used to
    /// `unwrap_or(false)`: a malformed or momentarily unreadable file
    /// read as "no server is metered", which is unlimited automatic
    /// spend on exactly the install the ceiling exists for (Codex sweep
    /// 24 Aug, F-10). Failing the other way costs one skipped automatic
    /// hunt on an install with no ceiling set, and the refusal names
    /// itself in the giveup clause.
    pub(super) fn hunt_metered(&self) -> bool {
        nzbkit::config::Config::load(&self.cfg_path)
            .map(|c| {
                c.servers
                    .iter()
                    .any(|s| s.enabled && !s.may_spend_on_measurement())
            })
            .unwrap_or(true)
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
            // Complete-only IN the SQL: filtering after the newest-first
            // LIMIT loses a complete copy older than 500 incompletes.
            let hits = self
                .with_index_read(|ix| ix.search_complete(&p.title, 500).ok())
                .unwrap_or_default();
            for r in hits.iter() {
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

    /// Put the surviving candidate on the queue and say so. Runnable in
    /// the ordinary case; HELD if some other live copy of the release
    /// holds it, which since 25 Aug 2026 is a state this road can reach
    /// - see below. Either way a replacement was placed, so the answer
    /// is `true` and the candidate loop stops: hunting a THIRD copy
    /// while a second is already live is the waste the caps exist for.
    ///
    /// [`DupeExempt::Row`], naming the row this hunt is replacing: the
    /// replacement IS a duplicate of the release that just failed, and
    /// that is the whole point - without the exemption the M14f hold
    /// would park the only copy that can still deliver.
    ///
    /// **ONE row, and this was a bare `allow_dupe = true` until 25 Aug
    /// 2026** (§290, Codex F-09). That bool switched BOTH duplicate arms
    /// off at once - the name arm and §292's same-post arm - against
    /// every record in both stores, and the argument above is true about
    /// the failed source row and about nothing else. Against any OTHER
    /// live copy of the release the hold is the correct answer, and it
    /// was being suppressed: a hunted copy started downloading beside a
    /// copy the user, an *arr or a watchlist had already queued.
    ///
    /// Not covered by the admission test above, and that is why this is
    /// its own defect rather than a second spelling of one: `hunt_one`
    /// holds each candidate to `spare::admits` against THE FAILED JOB's
    /// message-id set, so a candidate that is the same post as the row
    /// being replaced is already refused. The gap is the same question
    /// asked about a DIFFERENT live row, which is precisely what §292's
    /// arm exists to answer - and it was the arm being bypassed.
    ///
    /// Not covered by §290's byte ceiling either: `altspend`'s
    /// population is this mechanism's own `alt_from` chain, `hunt:`
    /// origins and the §96.3 breaker's stems, so an unrelated live copy
    /// somebody else queued is in none of them.
    ///
    /// The failed row stays exempt whichever store it is in. It is
    /// usually in HISTORY as Failed by the time the worker runs - park
    /// files it before `hunt_request` - and a Failed history row is not
    /// a collision target for either arm anyway; naming it here is what
    /// makes that true by construction rather than by timing, and covers
    /// the window in which it is still on the queue.
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
                DupeExempt::Row(&req.nzo_id),
            ),
            None => self.enqueue_as(
                None,
                &bytes,
                &cand.stem,
                &req.category,
                0,
                None,
                None,
                &origin,
                DupeExempt::Row(&req.nzo_id),
                None,
            ),
        };
        match out {
            Ok(e) => {
                // §282 item 14, BOTH halves: the new row records what
                // it replaced and why, the abandoned row records what
                // replaced it, and `altcand::switch_lines` renders them
                // on every surface. Before the emit, so a subscriber
                // that reads the queue on the event finds the clause
                // already there - and FIRST, because its answer is the
                // placement truth everything else here hangs on.
                // `enqueue` answers Ok for an add a pre-queue verdict
                // filed straight to history as Failed, and this arm
                // used to announce that as a replacement anyway: log,
                // `job.replaced`, and a `true` that stopped the
                // candidate loop with nothing running (Codex sweep
                // 24 Aug, F-08). A rejection is not a replacement:
                // say so, skip the event, and let the loop try the
                // next candidate.
                if !self.stamp_hunt_switch(req, &e.nzo_id, &cand.stem) {
                    info!(
                        target: "queue",
                        "{}: {} was fetched to replace {} but a pre-queue verdict \
                         filed it straight to history - trying the next candidate",
                        e.nzo_id, cand.stem, req.name
                    );
                    return false;
                }
                // §290: the replacement is an ordinary duplicate of
                // every live copy that is NOT the row it replaces, so
                // it can land held. Saying "queued" for a row parked at
                // Duplicate priority is the confusing sentence
                // `held_as_duplicate` exists to stop the add reply
                // telling, and it would be no less confusing here.
                let placed = if self.held_as_duplicate(&e.nzo_id) {
                    "was held behind a copy of it that is already live"
                } else {
                    "was queued in its place"
                };
                info!(
                    target: "queue",
                    "{}: {} could not complete, so {} {placed} ({})",
                    e.nzo_id, req.name, cand.stem, origin
                );
                // The event ring, which is what a WEBHOOK subscriber
                // hears - item 18's whole point being the user who is
                // not looking at the dashboard.
                //
                // IT IS ALSO TOASTED, since 24 Aug 2026, and this
                // comment has now been wrong in BOTH directions: it
                // claimed a toast that did not exist from the day the
                // file landed, was corrected to "not toasted" when item
                // 18 read the page hours later, and is corrected again
                // here by the change that built the arm. Check the page
                // before trusting a third version of this sentence.
                // `handleLifeEvents` in web/dashboard.html dispatches on
                // `e.kind` through a chain with NO fallthrough arm, and
                // carried neither kind - so an open tab silently dropped
                // both while every webhook subscriber was told. It now
                // has one arm for the pair, and that arm reads `by` to
                // stay quiet on the door the user clicked themselves.
                // What a looking user has always seen is item 14's
                // clause, rendered off the job row by
                // `altcand::switch_lines` - a state rather than a
                // moment, so it is there whenever they look and absent
                // at the instant it happens. The toast is that instant;
                // the two are complements and neither replaces the
                // other.
                //
                // ONE PAYLOAD SHAPE, TWO KINDS - §282 item 18's closing
                // decision, taken 24 Aug 2026. The keys here are the
                // keys `job.switched` carries (`promote_held_alternative`
                // and `altcand::alt_switch`): what replaced the job
                // (`nzo_id`, `name`, `category`), what was abandoned
                // (`replaces`, `replaces_name`), why (`reason`), and
                // which door (`by`). They were `failed_nzo_id` /
                // `failed_name` for the not quite four hours between
                // this file landing (12:42) and item 18 closing, and
                // carried neither
                // `category` nor `reason` - a third vocabulary for the
                // one thing a user experiences as "the release I queued
                // is gone and something else is downloading", which a
                // subscriber then had to special-case field by field.
                //
                // The KIND stays separate, and that is the substance of
                // the decision rather than an omission. A hunt is not a
                // switch: it spends NEW bytes and an indexer grab on a
                // release the user never queued, where both
                // `job.switched` doors promote a copy already held and
                // already paid for. `hooks::wants_lifecycle` matches an
                // exact kind or a `prefix.*` and NOTHING in the body, so
                // the kind is the only axis a webhook target's `events`
                // field can express - fold this into `job.switched` and
                // "tell me when you spend money hunting" stops being
                // sayable at all. A subscriber that does not care takes
                // `job.*` and reads one shape across both.
                //
                // `target` is this door's only, the way `rank` is the
                // promote door's only, and is omitted rather than nulled
                // on the other two for the reason written up there.
                //
                // THE FREE RENAME WINDOW WAS OPEN AND WAS NOT USED, on
                // purpose. `job.replaced` had never been in a released
                // binary when this landed (v1.2.2 is 23 Aug; the hunt is
                // e61b3d232, 24 Aug 12:42), so the kind could have been
                // renamed to item 18's sketched `job.hunt_*` at no
                // compatibility cost, and that will never be true again.
                // Rejected because a rename buys a subscriber nothing
                // that aligning the keys did not already buy, and the
                // one thing it would cost is real: the manual sentence
                // and 15 translations name kinds in prose.
                self.life_emit(
                    "job.replaced",
                    json!({
                        "nzo_id": e.nzo_id,
                        "name": cand.stem,
                        "category": req.category,
                        "replaces": req.nzo_id,
                        "replaces_name": req.name,
                        "reason": req.fail_message,
                        "by": "hunt",
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

    /// §282 item 14 on the HUNT road: record the switch on both rows, so
    /// `altcand::switch_lines` renders for a hunted replacement exactly
    /// as it does for a promoted spare and for a clicked offer.
    ///
    /// Item 14 was built for the two roads that run inside `park_gen`
    /// and stamped neither half here, which left the hunt - the one road
    /// that produces a switch the user did nothing at all to ask for -
    /// as the only one that said nothing anywhere. The reader item 14
    /// names in its own note is "watching an unfamiliar release name
    /// download right now", and that is precisely what a hunt produces.
    ///
    /// **Why this is a second write and not a field on the add.**
    /// `enqueue` builds the `Job` itself and has already saved the queue
    /// by the time it answers, so the clause costs one more write and
    /// one more save - the shape `stamp_refeed_depth` and
    /// `enqueue_fetched`'s failure-link stamp both take, and for the
    /// same reason: without the save a restart in the window loses the
    /// clause off a row that is going to run.
    ///
    /// **Both halves, or neither.** They are stamped only when the
    /// replacement really reached the QUEUE. `enqueue` answers `Ok` for
    /// an add it filed straight to history instead - a pre-queue script
    /// REJECT is the live shape - and a row that failed before it ran
    /// replaced nothing, so telling the abandoned row it was "replaced
    /// by" that is worse than saying nothing at all.
    ///
    /// **The abandoned row is the harder half, and it IS stamped.** The
    /// two older producers run inside `park_gen`, synchronously, with
    /// the failed job in hand; this one runs on the hunt worker some
    /// time later, by which point the record has been filed into history
    /// and may have been deleted or retried since.
    /// `history_upsert_if_present` is exactly the primitive for that -
    /// it is how the mover and the unlock task persist a late mutation -
    /// and its `Arc::ptr_eq` check under `HIST_IO` is what stops a
    /// delete that landed in the gap being resurrected by this append.
    /// A record no longer in history is simply not stamped, which is the
    /// honest answer: it was deleted or retried, and neither wants a
    /// "replaced by" clause.
    ///
    /// Returns whether the replacement was FOUND ON THE QUEUE and
    /// stamped. That answer is `hunt_enqueue`'s placement oracle: false
    /// means the add never became a live row (the pre-queue REJECT
    /// shape above), so no replacement happened and the caller must not
    /// announce one (Codex sweep 24 Aug, F-08).
    fn stamp_hunt_switch(&self, req: &HuntRequest, new_id: &str, new_name: &str) -> bool {
        // The CLAUSE carries `why_from_fail`'s stripped form, the same
        // call `promote_held_alternative` makes: the raw `fail_message`
        // is what an operator pastes into a bug report, and its build
        // stamp in the middle of "replaced X because Y" is noise about
        // the wrong build. The `job.replaced` event keeps the raw form,
        // as the promote path's `reason` does - which this comment
        // asserted from the day the file landed and which was not true
        // until item 18 closed on 24 Aug 2026, the event having carried
        // no `reason` key at all. The two forms of one sentence are the
        // point of the split, so a `reason` that arrives pre-stripped is
        // the regression to watch for here.
        let why = crate::serve::altcand::why_from_fail(&req.fail_message);
        let stamped = {
            let q = self.queue.lock_ok();
            match q.iter().find(|j| j.lock_ok().nzo_id == new_id) {
                Some(job) => {
                    let mut g = job.lock_ok();
                    g.alt_from = req.nzo_id.clone();
                    g.alt_from_name = req.name.clone();
                    g.alt_why = why;
                    true
                }
                None => false,
            }
        };
        if !stamped {
            return false;
        }
        self.save_queue();
        // ...and the abandoned row learns what replaced it. The lookup
        // and the write share ONE hold of the history lock, which is
        // what makes "it was in history when this was written" true
        // rather than likely: `retry` removes a record under that same
        // lock, so this either precedes the removal or finds nothing.
        let failed = {
            let h = self.history.lock_ok();
            let found = h.iter().find(|j| j.lock_ok().nzo_id == req.nzo_id).cloned();
            if let Some(j) = &found {
                let mut g = j.lock_ok();
                g.alt_to_name = new_name.to_string();
                // ...and it stops being due for an automatic retry. The
                // offer is shown precisely while a stamp sits past due and
                // unconsumed (a long live job, a pause, a min-free hold),
                // so leaving it armed re-queues a record this search has
                // already replaced.
                g.auto_retry_at = None;
                g.auto_retry_why = None;
            }
            found
        };
        // With NO job lock held, and outside the history lock:
        // `history_publish` takes both itself. The rescuing publish and
        // not the raw upsert: the write above DISARMED an overdue
        // auto-retry stamp, so a refused append the rewrite could still
        // rescue would reload the stamp at the next start and re-queue
        // the abandoned row beside the replacement this search just
        // added (Codex C11). Its present-check keeps a delete that
        // landed since from being resurrected.
        if let Some(failed) = failed {
            self.history_publish(&failed, || {
                format!(
                    "{}: the replaced row's disarmed retry did not reach the \
                     store - after a restart its overdue auto-retry queues it \
                     again beside the replacement",
                    failed.lock_ok().name
                )
            });
        }
        true
    }
}

// §282 item 20: the CLICKED road. A person is looking at a queue row
// that `altcand::terminal_reason` says cannot finish, and has asked for
// a replacement. Item 12 built the notice, the row badge, the switch
// endpoint and the drawer and deliberately left the search half out,
// saying so in its own note; section C then built the AUTOMATIC road
// only. Both halves are correct on their own and nobody owned the seam,
// so a user with nothing held got a sentence naming a setting and no way
// to ask.
//
// NOTHING BELOW SEARCHES A SECOND WAY. The pick list is
// `hunt_candidates` with the enqueue withheld: the same identity filter,
// the same ranking, the same dead-stem exclusion and the same cost
// ceilings, so a candidate a person can pick is exactly one the
// automatic road would have tried. The two refusals that differ are on
// [`Trigger`] and nowhere else.
impl Daemon {
    /// The doomed row, snapshotted for the gates - from the queue, or
    /// (§284) from history once it has actually failed.
    ///
    /// Three refusals live here rather than in [`hunt_gates`] because
    /// they are statements about the ROW rather than about hunting, and
    /// each of them is a state the dashboard cannot reach by drawing
    /// what it was told - reaching one means the record moved under the
    /// tab. Their sentences are `alt_switch`'s own, word for word, so
    /// the two buttons on one drawer never explain the same refusal two
    /// ways.
    ///
    /// **THE `fail_message` IS THE HINGE, and the two roads reach it
    /// differently for one reason: on the queue road nothing has failed
    /// yet, and on the parked road everything has.**
    ///
    /// Queued, the snapshot's `fail_message` is the sentence the
    /// abandoned row WILL carry if the user picks something: the
    /// verdict's failure lead, then its evidence, which is exactly what
    /// `alt_switch` writes. That is not decoration - `fail_kind` reads
    /// it by prefix, and it is what lets the age gate and the
    /// local-fault test below judge the clicked road on the same
    /// evidence as the automatic one instead of on the empty string a
    /// still-queued job carries.
    ///
    /// Parked, no synthesis is needed or wanted: the job failed, so it
    /// carries the real sentence, and that is the same string
    /// [`Daemon::hunt_request`] hands the automatic road off a job that
    /// has just died. So §284's road is the AUTOMATIC road's evidence
    /// reached by a click, which is why every gate below judges it
    /// correctly with no argument threaded through - and why it reaches
    /// the shape §284 item 2 is about, a job that died DURING the run
    /// with no health probe on it for `terminal_reason` to read.
    fn hunt_click_request(&self, nzo_id: &str) -> std::result::Result<HuntRequest, String> {
        let job = self
            .queue
            .lock_ok()
            .iter()
            .find(|j| j.lock_ok().nzo_id == nzo_id)
            .cloned();
        let Some(job) = job else {
            // §284. Resolved only once the queue has answered, so a row
            // that is in both stores for an instant is judged as the
            // queue row it is about to stop being - the same precedence
            // `altcand::alt_switch` takes, and it has to be the same or
            // the search and the switch would run different gates.
            return self.hunt_parked_request(nzo_id);
        };
        let g = job.lock_ok();
        // A HELD SPARE never gets a hunt, for the reason `offer_json`
        // already refuses it the offer (ac45c507e): a spare exists to
        // catch its primary's failure, it is not downloading anything,
        // and hunting a replacement FOR A SPARE is §4b's junk-queue
        // class. The button never renders on such a row - it is drawn
        // from `alt_offer` - so this refusal is the same guard at the
        // door a direct API call walks through (release-eve sweep S10,
        // 25 Aug 2026). If the spare is promoted and then proves dead,
        // THAT run gets the offer and this door as an ordinary row.
        if !g.held_for.is_empty() {
            return Err(
                "this row is a spare held for another download, so there is nothing \
                 to replace - promote it first if you want to run it"
                    .into(),
            );
        }
        if matches!(g.state, JobState::Downloading | JobState::Finishing) {
            return Err(
                "this download has already started - pause it first, or let it finish".into(),
            );
        }
        let Some((_, why, lead)) = crate::serve::altcand::terminal_reason(&g) else {
            return Err("nothing has concluded that this download cannot finish".into());
        };
        Ok(HuntRequest {
            nzo_id: g.nzo_id.clone(),
            name: g.name.clone(),
            origin: g.origin.clone(),
            fail_message: format!("{lead}: {why}"),
            // Synthesised for a job that has not failed - see the field.
            fail_code: None,
            nzb_path: g.nzb_path.clone(),
            category: g.category.clone(),
        })
    }

    /// §284: the same snapshot, off the history row of a job that has
    /// already failed.
    ///
    /// One gate, `altcand::parked_replaceable`, which is the SAME
    /// predicate the history row's own offer is drawn from - so a button
    /// that is on the page is a button this door will answer, and the
    /// bound on how far back an offer reaches is decided in exactly one
    /// place. Its refusal sentence is `alt_switch`'s parked one, word
    /// for word, for the reason the queue road's three are.
    fn hunt_parked_request(&self, nzo_id: &str) -> std::result::Result<HuntRequest, String> {
        let Some(job) = self.history_job(nzo_id) else {
            return Err("that download is no longer in the queue".into());
        };
        let g = job.lock_ok();
        if !crate::serve::altcand::parked_replaceable(&g) {
            return Err("another copy is no longer offered for that download".into());
        }
        Ok(HuntRequest {
            nzo_id: g.nzo_id.clone(),
            name: g.name.clone(),
            origin: g.origin.clone(),
            // The row's OWN verdict, not a synthesis: see the note on
            // the queue road above.
            fail_message: g.fail_message.clone(),
            fail_code: g.fail_code,
            nzb_path: g.nzb_path.clone(),
            category: g.category.clone(),
        })
    }

    /// Distinct releases of these targets that have already failed.
    ///
    /// The read-only half of what `hunt_one` gets back from
    /// `record_failure`, and it stays read-only on BOTH clicked roads -
    /// for two different reasons, which is worth setting out because
    /// §284 made the original one only half true.
    ///
    /// **QUEUED (§282 item 20): nothing has failed.** The row is still
    /// on the queue, its verdict is a pre-flight one, and recording a
    /// failure for a release that has not had one would feed the §96.3
    /// breaker evidence it did not earn - and that breaker is what
    /// decides whether an *arr is told to give a target up.
    ///
    /// **PARKED (§284): it has failed, and recording it here would be
    /// the SECOND time for the rows that count.** `park_gen` already
    /// ran `giveup_note_outcome` on that job, so a watchlist-origin
    /// release is in the store; a second record of one dead release
    /// would spend two of the user's `alt_max_copies` on it. (*arr rows
    /// never reach here at all - `hunt_gates` refuses them first, item
    /// 9.)
    ///
    /// **AND THE COUNT IS ZERO FOR MOST PARKED ROWS, which is not an
    /// oversight.** `giveup_note_outcome` returns early for anything
    /// that is neither *arr nor watchlist, so a job the user added by
    /// hand records nothing when it dies - `hunt_one` says so at its own
    /// `record_failure` and records there for exactly that reason. So on
    /// the parked road `alt_max_copies` bounds only what the breaker
    /// already knows about, and a hand-added release the user keeps
    /// clicking through is bounded by the clicking rather than by the
    /// number. That is the right way round: this ceiling exists to stop
    /// the DAEMON spending copies on its own initiative, and §282 item
    /// 12 calls the click "the default posture ... safe on any account
    /// type" precisely because a person is deciding each time. Making
    /// the cap bite here would mean recording, which is the double count
    /// above. The byte ceiling is unaffected and still applies on both
    /// roads: `hunt_spent` counts the `hunt:<target>` origins themselves
    /// rather than the breaker.
    fn hunt_copies_spent(&self, keys: &[String]) -> u32 {
        let st = self.giveup.lock_ok();
        keys.iter()
            .filter_map(|k| st.targets.get(k))
            .map(|t| t.stems.len() as u32)
            .max()
            .unwrap_or(0)
    }

    /// The gates and the ceilings both clicked doors run, in one place so
    /// the SEARCH and the PICK cannot answer differently. Returns the
    /// target keys and the byte budget.
    fn hunt_click_gates(
        &self,
        req: &HuntRequest,
    ) -> std::result::Result<(Parsed, Vec<String>, Option<u64>), String> {
        let policy = self.hunt_policy();
        let (p, keys) =
            hunt_gates(req, policy, unix_now(), Trigger::Clicked).map_err(|e| e.why())?;
        // Item 11's copy cap. The setting is "how many copies of one
        // release this may spend in total, the first attempt included",
        // so a user who set 2 and has watched 2 die is told that rather
        // than handed a third - and the sentence names the ceiling, so
        // the remedy is one setting away.
        let copies = self.hunt_copies_spent(&keys);
        if copies >= policy.max_copies {
            return Err(NoHunt::CopyCap(copies).why());
        }
        let budget = self
            .hunt_budget(&keys, policy, Trigger::Clicked)
            .map_err(|e| e.why())?;
        Ok((p, keys, budget))
    }

    /// §282 item 20: what a person may pick, ranked.
    ///
    /// Costs one search across the enabled indexers and NO grab: an
    /// indexer's daily grab budget is spent by [`Self::hunt_pick`], on
    /// the one copy the user actually chose. Nothing is enqueued here
    /// and nothing is downloaded.
    pub(in crate::serve) fn hunt_offer(&self, nzo_id: &str) -> std::result::Result<Value, String> {
        let req = self.hunt_click_request(nzo_id)?;
        let (p, keys, budget) = self.hunt_click_gates(&req)?;
        let mut cands = self.hunt_candidates(&req, &p, &keys);
        sort_best_first(&mut cands);
        // Refused before the list is cut, exactly as the automatic road
        // refuses before its fetch ceiling: an over-budget candidate
        // holding a slot would starve the affordable ones behind it. A
        // size of 0 is UNKNOWN and not free - see [`affordable`].
        let before = cands.len();
        cands.retain(|c| affordable(c.size, budget));
        // Said as the ceiling rather than as "nothing found", because
        // they are different facts with different remedies: one is a
        // setting, the other is the world.
        if cands.is_empty() && before > 0 {
            return Err(NoHunt::ByteCap.why());
        }
        cands.truncate(MAX_OFFER_ROWS);
        let rows: Vec<Value> = cands
            .iter()
            .map(|c| {
                json!({
                    "key": c.key(),
                    "name": c.stem,
                    "size": c.size,
                    "posted": c.posted,
                    "source": c.source(),
                })
            })
            .collect();
        self.hunt_remember(nzo_id, cands);
        Ok(json!({"candidates": rows}))
    }

    /// Keep this row's pick list for the click that follows it.
    fn hunt_remember(&self, nzo_id: &str, cands: Vec<Cand>) {
        let now = unix_now();
        let mut m = self.hunt.offers.lock_ok();
        m.retain(|_, o| now - o.at < OFFER_TTL_SECS);
        while m.len() >= OFFER_ROWS_CACHED {
            // Oldest out. `min_by_key` over at most a handful of
            // entries; a real LRU would be state to keep correct for
            // nothing.
            let Some(oldest) = m.iter().min_by_key(|(_, o)| o.at).map(|(k, _)| k.clone()) else {
                break;
            };
            m.remove(&oldest);
        }
        m.insert(nzo_id.to_string(), HuntOffers { at: now, cands });
    }

    /// The candidate `key` names on this row's cached list, if it is
    /// still there and still fresh.
    fn hunt_remembered(&self, nzo_id: &str, key: &str) -> Option<Cand> {
        let now = unix_now();
        let m = self.hunt.offers.lock_ok();
        let o = m.get(nzo_id).filter(|o| now - o.at < OFFER_TTL_SECS)?;
        o.cands.iter().find(|c| c.key() == key).cloned()
    }

    /// §282 item 20: the user picked one.
    ///
    /// **Through the EXISTING switch path, and that is the whole design.**
    /// The candidate is fetched, held to item 6's admission test, then
    /// parked as a HELD SPARE of the doomed row - and
    /// [`Daemon::alt_switch`] promotes it. So the abandoned job is failed
    /// with the verdict's own sentence and the failure LEAD that tells an
    /// *arr what happened, item 14's "what replaced what" clause is
    /// written on both rows by the code that already writes it, and
    /// `job.switched` is emitted with `by: "user"` - none of which is
    /// re-spelled here. A second copy of that sequence is how the two
    /// halves of §282 would drift into two accounts of one event.
    ///
    /// The gates are re-run rather than trusted from the search: the
    /// list may be half an hour old, and the row, the settings and the
    /// budget can all have moved since it was drawn.
    pub(in crate::serve) fn hunt_pick(
        &self,
        nzo_id: &str,
        key: &str,
    ) -> std::result::Result<String, String> {
        let req = self.hunt_click_request(nzo_id)?;
        let (_, keys, budget) = self.hunt_click_gates(&req)?;
        let cand = self
            .hunt_remembered(nzo_id, key)
            .ok_or("that list of copies is out of date - search again")?;
        if !affordable(cand.size, budget) {
            return Err(NoHunt::ByteCap.why());
        }
        let Some((bytes, headers)) = self.hunt_fetch(&cand) else {
            return Err(
                "that copy's .nzb could not be fetched from the indexer that \
                        offered it - the log says why"
                    .into(),
            );
        };
        // ITEM 6's admission test, `spare`'s rather than a second copy of
        // it, and on the ADMISSION side of its argument (`unknown =
        // false`): a copy that is the same post fails identically, and a
        // pair that cannot be compared is a whole download started on a
        // guess. Same call, same answer, as the automatic road.
        let want = std::fs::read(&req.nzb_path)
            .ok()
            .and_then(|b| nzbkit::nzb::Nzb::parse(&b).ok())
            .map(|n| spare::post_ids(&n));
        let got = nzbkit::nzb::Nzb::parse(&bytes).ok();
        let admitted = match (want.as_ref(), got.as_ref()) {
            (Some(w), Some(g)) => spare::admits(w, &spare::post_ids(g), false),
            _ => false,
        };
        if !admitted {
            return Err(
                "that copy is the same post as the download that cannot finish (or \
                        one of the two .nzb files could not be read), so it would fail the \
                        same way"
                    .into(),
            );
        }
        // `hunt:<target key>` and not the spare origin: the byte
        // accounting item 11 reads is per TARGET and reads the origin,
        // so a copy picked by hand has to count against the same ceiling
        // a hunted one does. Both roads spend one copy of one release.
        let origin = hunt_origin(&keys[0]);
        let e = self
            .hunt_hold(&req, &cand, &bytes, headers.as_ref(), &origin)
            .map_err(|e| format!("that copy could not be queued: {e}"))?;
        if let Some(err) = self.alt_switch(&req.nzo_id, &e) {
            // The switch refused, so the row we just parked is a
            // download nobody asked for, held against a job that is
            // still on the queue. Take it back off rather than leave it:
            // a spare the user cannot see the reason for is §4b's junk
            // queue arriving by a new road.
            self.hunt_unhold(&e);
            return Err(err);
        }
        self.hunt.offers.lock_ok().remove(nzo_id);
        info!(
            target: "queue",
            "{e}: {} cannot finish, so {} was picked by hand in its place ({origin})",
            req.name, cand.stem
        );
        Ok(e)
    }

    /// Park the picked copy as a held spare of the doomed row, so
    /// `alt_switch` can promote it.
    ///
    /// `enqueue_as` with `hold_for` rather than `enqueue_fetched`,
    /// because that one has no `hold_for` argument and lives in
    /// `serve/daemon.rs`, which is on its size-gate ceiling. The one
    /// thing it does that `enqueue_as` does not is the failure-link
    /// stamp, which is eleven lines and is here - and it needs its own
    /// save for the reason that one states: `enqueue` saved the queue
    /// before the stamp existed, so a restart in the window would lose
    /// the link off a row that is about to run.
    fn hunt_hold(
        &self,
        req: &HuntRequest,
        cand: &Cand,
        bytes: &[u8],
        fetched: Option<&Fetched>,
        origin: &str,
    ) -> Result<String> {
        let e = self.enqueue_as(
            None,
            bytes,
            &cand.stem,
            &req.category,
            SAB_DEFAULT_PRIORITY,
            None,
            None,
            origin,
            DupeExempt::Nobody,
            Some(&req.nzo_id),
        )?;
        if let Some(f) = fetched.filter(|f| !f.failure_link.is_empty()) {
            let stamped = {
                let q = self.queue.lock_ok();
                match q.iter().find(|j| j.lock_ok().nzo_id == e.nzo_id) {
                    Some(job) => {
                        let mut g = job.lock_ok();
                        g.failure_link = f.failure_link.clone();
                        g.failure_host = f.host.clone();
                        g.failure_https = f.https;
                        true
                    }
                    None => false,
                }
            };
            if stamped {
                self.save_queue();
            }
        }
        Ok(e.nzo_id)
    }

    /// Take a parked pick back off the queue after a refused switch.
    ///
    /// The spool copy goes with the row. `hunt_hold` wrote one through
    /// `enqueue_as`, and this removal is the last record that names it -
    /// a survivor under the adoptable `SABnzbd_nzo_nzbfast*.nzb` name is
    /// re-enqueued by `recover_orphaned_spool` at the next start, as a
    /// fresh download of the copy the user was just told could not be
    /// switched to. Unlike the other `drop_spool` callers this one is
    /// not fault-conditioned: every refused switch left the orphan
    /// (Codex sweep 24 Aug, F-04).
    ///
    /// **UNLINK BEFORE `save_queue`, on purpose** (sweep 9, finding 4,
    /// which read the order as a defect and proposed the inverse). The
    /// rename and the durable write are two syscalls and nothing makes
    /// them one, so SOME crash window exists whichever way round they
    /// go; what differs is what the next start finds. Take them in
    /// turn, remembering that `save_queue` writes through a temp file
    /// and renames, so a crash during it leaves the PREVIOUS queue.json
    /// - the one that still holds this row:
    ///
    /// * unlink, then save (this order): the row comes back naming an
    ///   NZB that is gone. A broken spare, held at -3, that promotes
    ///   into a parse failure. Bad, and bounded.
    /// * save, then unlink: the row is gone and the file is still under
    ///   the adoptable name, so `recover_orphaned_spool` enqueues it -
    ///   a real download, un-held, of the very copy the user was just
    ///   told could not be switched to. That is F-04 above, and it is
    ///   the worse of the two.
    /// * mask to `.deleting`, save, unlink - the shape the sweep asked
    ///   for. Its second window is benign (recovery skips a masked
    ///   name), but its FIRST is not: queue.json is not rewritten until
    ///   the save, so a crash between the rename and it restores the
    ///   same broken row as the first option AND strands the masked
    ///   file, which nothing then names. One window traded for two, one
    ///   of them identical. Measured against the loader
    ///   (`recover_orphaned_spool` skips a name that fails
    ///   `strip_suffix(".nzb")`, and skips any file whose allocator
    ///   number matches a live row's nzo_id), not assumed.
    ///
    /// So the order below prefers a stuck row over an unwanted
    /// download, and this block is where it says so. Do not invert it
    /// without a journal to make the pair atomic.
    fn hunt_unhold(&self, nzo_id: &str) {
        let nzb = {
            let mut q = self.queue.lock_ok();
            let before = q.len();
            let mut nzb = None;
            q.retain(|j| {
                let g = j.lock_ok();
                if g.nzo_id == nzo_id {
                    nzb = Some(g.nzb_path.clone());
                    false
                } else {
                    true
                }
            });
            if q.len() == before { None } else { nzb }
        };
        if let Some(nzb) = nzb {
            drop_spool(&nzb);
            self.save_queue();
        }
    }
}

#[cfg(test)]
#[path = "hunt_tests.rs"]
mod hunt_tests;
