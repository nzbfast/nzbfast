//! TODO §77: the advisory pre-flight score - the failure diagnostics run
//! backwards.
//!
//! [`crate::diag`] answers "why did this job fail?" from a post-mortem
//! census of a run that already spent the bandwidth. Everything it reads
//! - which servers said 430, how many segments never arrived, how old the
//! post is - can be sampled for a few hundred bytes BEFORE the download
//! starts, and that is all this module is: STAT a handful of articles
//! across every configured server at enqueue, and put the answer on the
//! queue row so "posted four days ago, on none of your three servers"
//! arrives before 60 GB does rather than at 97%.
//!
//! **It is advisory and it must stay that way.** A 430 from every server
//! is not proof a post is dead: a freshly posted article 430s everywhere
//! until it propagates, and at that moment it is indistinguishable from
//! one that was taken down (memory `nzbfast-retry-propagation-trap`, and
//! [`crate::diag::GONE_MIN_AGE_DAYS`], which exists for exactly this).
//! So nothing here may fail a job, block a job, or remove a job from the
//! queue. The strongest thing a red verdict is allowed to do is SINK the
//! job in start order behind healthier ones, and only when the operator
//! has turned that on.
//!
//! The other half of the same rule: a sample of eight articles out of
//! nine thousand cannot measure how complete a post is. It can only ever
//! say "of the ones I asked about, this many were not there", so every
//! surface renders the sampled count beside the verdict and none of them
//! phrases it as a percentage.
//!
//! And the green verdict has a blind spot the sample size has nothing
//! to do with: STAT reports that an article ANSWERED, not that its
//! body is intact, and a small number of providers answer for removed
//! articles with dummy data instead of refusing them. Such a post
//! reads green here at any K. The false-green mode is written up in
//! `nzbkit::preflight`; the download's own CRC is what catches it.

use crate::diag::GONE_MIN_AGE_DAYS;

/// Articles sampled per job. Small on purpose: the whole point is that
/// this costs a round trip, not a download, and the marginal article
/// buys very little once the first few have answered - a post that is
/// gone is gone at every offset, and one that is short in one place is
/// exactly what a sample cannot promise to find.
pub(crate) const SAMPLE_K: usize = 8;
/// Sampled on a big job, where the bandwidth a wrong answer costs is
/// worth another handful of STATs.
pub(crate) const SAMPLE_K_LARGE: usize = 16;
/// Jobs at or above this take [`SAMPLE_K_LARGE`].
pub(crate) const LARGE_JOB_BYTES: u64 = 20_000_000_000;
/// §294: the LOSS-RATE sample, run once when the first burst lands
/// anything but green. Eight STATs answer "is this post gone"; they
/// cannot answer "is the damage inside what the recovery set covers",
/// because the Wilson interval on 8 draws spans most of the axis.
/// Sixty-four narrows it enough for [`score_completable`] to separate
/// repairable from short (the corpus test in this file measures the
/// difference), and it still costs one connectionful of STATs on an
/// idle daemon, only ever on a post that already looks troubled.
pub(crate) const ESCALATE_K: usize = 64;

/// Probes one job may ever run: the one at enqueue, and one re-check if
/// it is still sitting in the queue an hour later (a post that was
/// mid-propagation at add time has usually finished by then, and an
/// amber that stays amber is worth knowing about). Bounded so a job
/// parked in a paused queue for a week does not probe forever.
pub(crate) const MAX_PROBES: u32 = 2;
/// How long a queued job must sit before the second probe.
pub(crate) const RECHECK_AFTER_SECS: i64 = 3600;

/// Availability of one article on one server, as the sampler saw it.
/// Mirrors [`nzbkit::preflight::Avail`] - the STAT normalizer there is
/// the one both the `check` command and this share, so provider quirks
/// on "missing" versus "delayed" are decided in exactly one place.
pub(crate) use nzbkit::preflight::Avail;

/// Where a job's post-health verdict falls. Three buckets and no score
/// out of ten: the evidence is a handful of STATs, and any finer grain
/// would be inventing precision the sample does not have.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Bucket {
    /// Every sampled article is on at least one server that answered.
    Green,
    /// Sampled articles are missing everywhere, but the post is younger
    /// than propagation explains. Optimistic on purpose.
    Amber,
    /// Sampled articles are missing everywhere and the post is old
    /// enough that propagation is no longer the explanation.
    Red,
}

impl Bucket {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Bucket::Green => "green",
            Bucket::Amber => "amber",
            Bucket::Red => "red",
        }
    }

    pub(crate) fn from_str(s: &str) -> Option<Bucket> {
        match s {
            "green" => Some(Bucket::Green),
            "amber" => Some(Bucket::Amber),
            "red" => Some(Bucket::Red),
            _ => None,
        }
    }
}

/// §294: the joint answer to the question the two colors never ask -
/// "will this job COMPLETE" - computed by [`score_completable`] from
/// the sampled loss rate against the recovery capacity the NZB
/// declares. ADVISORY everywhere, exactly like the buckets: nothing
/// may fail or skip a job on this value (`post_health_fail` stays the
/// only fail gate, §138's public commitment).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Completable {
    /// No sampled payload loss: the download does not need repair to
    /// finish, whatever state the recovery set is in.
    Yes,
    /// Sampled loss, and the declared recovery covers even the
    /// pessimistic end of it.
    WithRecovery,
    /// The confidence interval straddles the line - the sample cannot
    /// separate "repairable" from "short".
    Doubtful,
    /// Even the OPTIMISTIC end of the sampled loss exceeds what the
    /// recovery set can fund: this download fails, and it is knowable
    /// before the first payload byte.
    No,
}

impl Completable {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Completable::Yes => "yes",
            Completable::WithRecovery => "with-recovery",
            Completable::Doubtful => "doubtful",
            Completable::No => "no",
        }
    }

    pub(crate) fn from_str(s: &str) -> Option<Completable> {
        match s {
            "yes" => Some(Completable::Yes),
            "with-recovery" => Some(Completable::WithRecovery),
            "doubtful" => Some(Completable::Doubtful),
            "no" => Some(Completable::No),
            _ => None,
        }
    }
}

/// What one server said about the sampled articles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ServerAnswer {
    pub host: String,
    /// `matrix[i]` for sampled article `i`, in sample order.
    pub cells: Vec<Avail>,
}

impl ServerAnswer {
    /// Did this server say anything definite at all? A host that refused
    /// the login, or that we never reached, leaves every cell `Unknown`
    /// and must be dropped from the verdict rather than counted as a
    /// vote either way - see [`score`].
    pub(crate) fn answered(&self) -> bool {
        self.cells.iter().any(|c| *c != Avail::Unknown)
    }

    /// (have, missing) over the cells this server actually answered.
    pub(crate) fn counts(&self) -> (u32, u32) {
        let have = self.cells.iter().filter(|c| **c == Avail::Have).count() as u32;
        let missing = self.cells.iter().filter(|c| **c == Avail::Missing).count() as u32;
        (have, missing)
    }
}

/// A job's pre-flight verdict, as carried on the Job record and rendered
/// on the queue row.
///
/// Every field the UI shows is here in NUMBERS, and `reason` is English
/// wire text: the dashboard composes its own sentence in the user's
/// language from the counts (the same division of labour as
/// [`crate::serve::Job::unpack_blocked_by`]), and `reason` is what the
/// API, the log line and the failure summary use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PostHealth {
    pub bucket: Bucket,
    pub reason: String,
    /// Articles STATed per server.
    pub sampled: u32,
    /// Sampled articles on at least one server that answered.
    pub present: u32,
    /// Sampled articles on NONE of the servers that answered. The number
    /// the buckets turn on, and the one that is never a completeness
    /// percentage - `absent` of `sampled`, always both.
    pub absent: u32,
    /// Servers that gave a definite answer about at least one article.
    pub answered: u32,
    /// Servers the probe tried.
    pub servers: u32,
    /// Per server that answered: (host, present, missing) over the
    /// sample. The census, inverted and run before the download instead
    /// of after it - and the only part of the verdict that separates
    /// "nobody has this" from "the cheap block account does not".
    ///
    /// Numbers, not a sentence, so the dashboard can render it in the
    /// user's own language beside the per-server contribution table it
    /// already draws for the active download.
    pub per_server: Vec<(String, u32, u32)>,
    /// Age in days of the youngest article in the post; 0 for an NZB
    /// with no usable dates, which reads as fresh (unknown is not old).
    pub age_days: u32,
    /// Unix seconds the probe ran.
    pub checked_at: i64,
    /// How many probes this job has had. See [`MAX_PROBES`].
    pub probes: u32,
    /// The user has reordered or re-prioritized this job since the
    /// probe, so the optional auto-defer no longer sinks it.
    ///
    /// The VERDICT survives - it is evidence about the post and the row
    /// keeps saying so - and only the scheduling effect is dropped. Same
    /// rule as the slow-job watchdog, whose `deferred` flag a manual
    /// reorder clears: once the user has asserted an order, a guess made
    /// from eight STATs does not get to argue with it.
    pub waived: bool,
    /// TODO §282 item 1: the RECOVERY set's own verdict, scored
    /// separately and never folded into the buckets above.
    ///
    /// Two numbers on the job, never one widened bucket. Every field
    /// from `bucket` down to `absent` is a claim about the PAYLOAD, and
    /// three separate consumers - the amber propagation guard, the
    /// optional auto-defer, and [`PostHealth::no_server_can_supply`] -
    /// read them as exactly that. A recovery volume's absence is not
    /// payload absence, so widening them to cover both would quietly
    /// change what all three mean. `None` until the prober has an
    /// answer, and forever on a post that carries no PAR2 at all.
    pub recovery: Option<RecoveryHealth>,
    /// §294: the joint verdict, or `None` on a record from before it
    /// existed (or scored by something that could not compute it).
    /// Always rebuilt by the prober alongside the buckets; see
    /// [`score_completable`].
    pub completable: Option<Completable>,
}

/// TODO §282 item 1: what pre-flight learned about a job's PAR2
/// recovery set, as its own verdict beside [`PostHealth`].
///
/// The gap this closes, from the 24 Aug 2026 incident §282 is written
/// against: two jobs failed with the payload 99.2% and 99.8% intact
/// because the RECOVERY set was the half the provider would not serve
/// (`fetched 68.9 MB of recovery data in 229.09s (1206 article
/// failures)` against a 1024 MB ask). The pre-flight sampler could not
/// have seen it, by construction - the payload sampler skips
/// `nzbkit::nzb::FileKind::Par2Volume` outright, so it sampled the one
/// half of the post that was healthy. Both jobs badged GREEN.
///
/// Same honesty rules as the payload verdict, and for the same reasons.
/// The counts are `absent` of `sampled`, never a percentage. A host
/// that never answered is dropped rather than counted - see [`tally`],
/// which both verdicts are built from precisely so that rule cannot
/// drift between them. A clean answer here is not a promise: STAT
/// reports that an article ANSWERED, not that its bytes are intact, and
/// the false-green mode on a takedown that replaces the body rather
/// than deleting it is written up in `nzbkit::preflight`'s module
/// header. And nothing here may fail a job - see [`score_recovery`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecoveryHealth {
    pub bucket: Bucket,
    pub reason: String,
    /// Recovery articles STATed per server.
    pub sampled: u32,
    /// Sampled recovery articles on at least one server that answered.
    pub present: u32,
    /// Sampled recovery articles on NONE of the servers that answered.
    pub absent: u32,
    /// Servers that gave a definite answer about at least one of them.
    pub answered: u32,
    /// Servers the probe tried.
    pub servers: u32,
    /// Per server that answered: (host, present, missing).
    pub per_server: Vec<(String, u32, u32)>,
    /// PAR2 files the NZB declares - index and volumes together. The
    /// reach of the sample, not a claim about the set's block count.
    pub volumes: u32,
    /// Did a real BODY of a recovery article arrive and parse as a PAR2
    /// set? `Some(true)` is the strongest evidence this module can
    /// obtain - those bytes were served, not merely acknowledged.
    /// `Some(false)` is deliberately WEAKER than it looks and is scored
    /// as such; [`score_recovery`] has the argument. `None` = the fetch
    /// was not attempted.
    pub fetched: Option<bool>,
}

impl RecoveryHealth {
    /// Is there anything here worth saying? Green is the quiet case and
    /// the queue row has nothing to add to what the payload badge
    /// already says.
    pub(crate) fn doubtful(&self) -> bool {
        self.bucket != Bucket::Green
    }

    /// §282 item 12: is the recovery set UNOBTAINABLE, as strongly as
    /// this evidence can say it? The incident this whole section is
    /// written against, in one predicate.
    ///
    /// Deliberately the same four clauses as
    /// [`PostHealth::no_server_can_supply`], and for the same reasons -
    /// every configured server answered (a silent host had no say),
    /// every sampled recovery article was missing, `servers > 0` so an
    /// empty fleet is never unanimous, and the propagation age gate
    /// rides in via Red. Red on its own is nowhere near enough: it needs
    /// only `absent > 0` among the hosts that answered, which is a fleet
    /// having a bad minute as readily as a dead recovery set.
    ///
    /// WHAT THIS IS FOR, and what it is NOT for. It is read by
    /// `serve::altcand` to put a notice and a button on the queue row,
    /// which the user then clicks or ignores. It is NOT a give-up
    /// predicate and must never become one: `post_health_fail` is OFF by
    /// default as a public commitment on issue #29 (§138), it reads the
    /// PAYLOAD fields only, and `score_recovery`'s own header says
    /// nothing it returns may fail a job. Offering somebody a button is
    /// not failing their download.
    pub(crate) fn unobtainable(&self) -> bool {
        self.bucket == Bucket::Red
            && self.servers > 0
            && self.answered == self.servers
            && self.sampled > 0
            && self.absent == self.sampled
    }
}

/// §295: where a held spare's probed health puts it in the PROMOTION
/// order - lower is promoted first. Worst of the payload and recovery
/// buckets, because a spare whose recovery set is dead fails exactly
/// like one whose payload is (that is §282's founding incident).
///
/// Green 0, unprobed 1, Amber 2, Red 3. Unprobed sits ABOVE amber on
/// purpose: amber is probed evidence that sampled articles are missing
/// somewhere, unprobed is no evidence at all, and promotion is choosing
/// where to spend a full download - known trouble ranks behind not
/// knowing. Only the ORDER matters here; nothing may fail or skip a
/// spare on this number (an all-red ladder still promotes its least-red
/// rung, which is the pre-§295 behaviour for every band tie).
pub(crate) fn promote_band(h: Option<&PostHealth>) -> u32 {
    let Some(h) = h else { return 1 };
    let of = |b: Bucket| match b {
        Bucket::Green => 0,
        Bucket::Amber => 2,
        Bucket::Red => 3,
    };
    of(h.bucket).max(h.recovery.as_ref().map_or(0, |r| of(r.bucket)))
}

impl PostHealth {
    /// Should the optional auto-defer sink this job? Red only: an amber
    /// is a post that is probably still landing, and sinking it is the
    /// one thing that would make the wait longer.
    pub(crate) fn sinks(&self) -> bool {
        self.bucket == Bucket::Red && !self.waived
    }

    /// TODO §138: does this verdict clear the bar the OPT-IN early
    /// give-up needs (`post_health_fail`)? Every other surface in this
    /// module is advisory; this is the one predicate a job can be failed
    /// on, so it is deliberately much narrower than [`Self::sinks`].
    ///
    /// Red is the floor, not the bar. Red only needs `absent > 0` among
    /// the servers that ANSWERED, and that is nowhere near enough to end
    /// a release on: a fleet where two hosts of three timed out, or a
    /// post short one article of eight, is red and may still download
    /// perfectly. Four things on top, and every one of them is load
    /// bearing:
    ///
    /// * **every configured server answered** (`answered == servers`) -
    ///   a host that stayed silent had no say, and "no server can supply
    ///   this" is a claim about the whole fleet, not about the subset
    ///   that happened to be reachable this minute. This is the promise
    ///   in issue #29's accepted shape, in one comparison;
    /// * **every sampled article was missing** (`absent == sampled`) -
    ///   a partially short post is what PAR2 is for, and a sample of
    ///   eight cannot tell "short" from "beyond repair" (that estimate
    ///   is the reporter's wishlist, which was NOT promised);
    /// * `servers > 0`, so an empty fleet is never unanimous;
    /// * **not waived** - the user has reordered or re-prioritized this
    ///   job since the probe, which is them asserting they want it. The
    ///   defer honours that (see [`Self::sinks`]) and the far heavier
    ///   action must honour it at least as much.
    ///
    /// The age guard rides in via Red: below [`GONE_MIN_AGE_DAYS`] the
    /// verdict is Amber whatever the servers said, so a post still
    /// propagating can never reach this. That is the whole
    /// `nzbfast-retry-propagation-trap` guard and it is the reason this
    /// takes a [`PostHealth`] instead of raw counts.
    ///
    /// Note what is still NOT proven here: a backbone that hiccups for
    /// five minutes 430s an old post on every server too, and this will
    /// believe it. That residual is why the setting is off by default
    /// and says so on its own row - the honest trade is "I would rather
    /// lose the occasional good release than spend the bandwidth", and
    /// it is the operator's to make, not ours.
    pub(crate) fn no_server_can_supply(&self) -> bool {
        self.bucket == Bucket::Red
            && !self.waived
            && self.servers > 0
            && self.answered == self.servers
            && self.sampled > 0
            && self.absent == self.sampled
    }
}

/// The union both verdicts in this module are built from: who answered,
/// what they said about the sample, and what that makes of it. `None`
/// when nothing was learned.
///
/// Shared rather than copied, because the two rules that are easy to get
/// wrong are the same rule for the payload and for the recovery set, and
/// a copy is where they drift apart. Both are spelled out inside.
struct Tally {
    sampled: u32,
    present: u32,
    absent: u32,
    answered: u32,
    servers: u32,
    /// Per server that answered: (host, present, missing).
    per_server: Vec<(String, u32, u32)>,
}

fn tally(answers: &[ServerAnswer]) -> Option<Tally> {
    let servers = answers.len() as u32;
    // A host that never answered is not a vote. Counting its silence as
    // "has the article" (which is what a plain all-servers union does,
    // since Unknown is deliberately not Missing) means one server with a
    // wrong password paints every post in the queue green; counting it
    // as "missing" would paint them all red. Neither is evidence, so it
    // leaves the room, and `answered` vs `servers` says how many did.
    let voting: Vec<&ServerAnswer> = answers.iter().filter(|a| a.answered()).collect();
    let sampled = voting.first().map_or(0, |a| a.cells.len());
    if voting.is_empty() || sampled == 0 {
        return None;
    }
    // Absent = no server that answered had it. An UNKNOWN cell inside an
    // otherwise-answering server still blocks the verdict for that
    // article: a session that died halfway through the pipeline knows
    // nothing about the ids it never got to, and pre-flight must never
    // manufacture a miss.
    //
    // `get`, not `[i]`: the prober hands every server a row of the same
    // length, but a scoring function that panics on a ragged matrix is
    // one refactor away from taking the daemon down, and a row too short
    // to answer about article `i` is exactly the "did not say" case the
    // line above already handles.
    let absent = (0..sampled)
        .filter(|&i| {
            voting
                .iter()
                .all(|a| a.cells.get(i) == Some(&Avail::Missing))
        })
        .count() as u32;
    // An article NO voting server gave a definite answer about was never
    // really sampled: the probe was cut short - the 20 s timeout, the
    // stand-down when a download starts, a mid-batch read error on every
    // server. Unknown must never manufacture a miss (above), but the
    // Green sentence claims "all N sampled article(s) are present", and
    // for these cells nobody was asked. With no definite miss elsewhere
    // either, nothing was LEARNED: no verdict, same as an unanswered
    // probe, rather than a latched green that unasked articles ride
    // along on. A definite miss elsewhere still buckets below - misses
    // are real evidence however short the probe fell.
    let unanswered = (0..sampled)
        .filter(|&i| {
            voting
                .iter()
                .all(|a| !matches!(a.cells.get(i), Some(&Avail::Have) | Some(&Avail::Missing)))
        })
        .count() as u32;
    let present = sampled as u32 - absent;
    let answered = voting.len() as u32;
    let sampled = sampled as u32;
    if absent == 0 && unanswered > 0 {
        return None;
    }
    Some(Tally {
        sampled,
        present,
        absent,
        answered,
        servers,
        per_server: voting
            .iter()
            .map(|a| {
                let (have, missing) = a.counts();
                (a.host.clone(), have, missing)
            })
            .collect(),
    })
}

/// Score a completed sample. `None` when nothing was learned - no server
/// answered, or there was nothing to sample - because a badge with no
/// evidence behind it is worse than no badge.
///
/// `age_days` is the age of the YOUNGEST article in the post, the same
/// figure [`crate::diag::LossCauses::post_age_days`] carries and for the
/// same reason: a fill or a repost tops an old NZB up with new articles,
/// and it is the newest posting that decides whether propagation is
/// still a live explanation.
pub(crate) fn score(
    answers: &[ServerAnswer],
    age_days: u32,
    at: i64,
    probes: u32,
) -> Option<PostHealth> {
    let Tally {
        sampled,
        present,
        absent,
        answered,
        servers,
        per_server,
    } = tally(answers)?;
    // The whole guard, in one line: missing everywhere is only evidence
    // about the POST once the post is older than propagation. Below the
    // threshold - and for a dateless NZB, which reads as age 0 - the
    // optimistic reading stands.
    let bucket = if absent == 0 {
        Bucket::Green
    } else if age_days < GONE_MIN_AGE_DAYS {
        Bucket::Amber
    } else {
        Bucket::Red
    };
    let mut reason = match bucket {
        Bucket::Green => format!(
            "pre-flight: all {sampled} sampled article(s) are on at least one of \
             {answered} server(s)"
        ),
        Bucket::Amber => format!(
            "pre-flight: {absent} of {sampled} sampled article(s) are on none of the \
             {answered} server(s) that answered, but the post is only {age_days} day(s) \
             old - a post still propagating looks exactly like this, so this is a \
             warning and nothing more"
        ),
        Bucket::Red => format!(
            "pre-flight: {absent} of {sampled} sampled article(s) are on none of the \
             {answered} server(s) that answered, and at {age_days} day(s) old the post \
             is past the point where propagation explains it"
        ),
    };
    // The census, inverted: who has what. "Missing everywhere" and
    // "missing on the one server that happens to be cheapest" are very
    // different situations and the counts alone cannot tell them apart -
    // this is the same reasoning that puts the per-server table in the
    // failure diagnostics, run before the download instead of after it.
    if bucket != Bucket::Green {
        reason.push_str(&format!(
            "; per server: {}",
            per_server_clause(&per_server, sampled)
        ));
    }
    // Both halves of the honesty clause. The sample size, because
    // "2 of 8" is not "25% of the release is missing" and the row must
    // never read like it is; and any server that stayed silent, because
    // its copy was not consulted and the verdict is thinner than the
    // server count suggests.
    if servers > answered {
        reason.push_str(&format!(
            "; {} of {servers} server(s) did not answer and were not counted",
            servers - answered
        ));
    }
    Some(PostHealth {
        bucket,
        reason,
        per_server,
        sampled,
        present,
        absent,
        answered,
        servers,
        age_days,
        checked_at: at,
        probes,
        waived: false,
        // Hung on afterwards by the prober, which is the only caller
        // that has a recovery sample to score. Keeping it out of this
        // signature keeps the payload verdict a function of the payload
        // evidence and nothing else. Same story for the §294 joint
        // verdict: it needs the byte totals and the recovery score,
        // neither of which is payload evidence.
        recovery: None,
        completable: None,
    })
}

/// The per-server census as one clause: who has how many of the sample.
///
/// "Missing everywhere" and "missing on the one server that happens to
/// be cheapest" are very different situations and the counts alone
/// cannot tell them apart - the same reasoning that puts the per-server
/// table in the failure diagnostics, run before the download instead of
/// after it.
fn per_server_clause(per_server: &[(String, u32, u32)], sampled: u32) -> String {
    per_server
        .iter()
        .map(|(host, have, _)| format!("{host} ({have}/{sampled} present)"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// TODO §282 item 1: score the RECOVERY set's sample, entirely apart
/// from the payload's.
///
/// `fetched` is what a real BODY of a recovery article did:
/// `Some(true)` it arrived and parsed as a PAR2 set, `Some(false)` the
/// attempt came back with nothing, `None` no attempt was made.
///
/// **`Some(false)` is scored more softly than it reads, on purpose.**
/// `nzbkit::preflight::probe_recovery_set` answers `None` for every
/// failure it can have - the article refused, the body undecodable, no
/// valid Main packet in the couple of articles it drew - and it cannot
/// say which. On a post with no `.par2` index the probe has to guess at
/// the head and tail of a recovery VOLUME, where the Main packet may
/// simply be somewhere else, so a failed fetch over a perfectly healthy
/// set is a real shape and not a rare one. Treating it as proof would
/// paint every such post red. So on its own it can only reach Amber -
/// enough that the row stops badging green, which is the whole ask -
/// and Red needs the STAT sample to have found recovery articles
/// missing on every server that answered, exactly as the payload
/// verdict does.
///
/// The age guard is the same guard and is here for the same reason
/// ([`crate::diag::GONE_MIN_AGE_DAYS`], memory
/// `nzbfast-retry-propagation-trap`): a recovery set posted yesterday
/// that 430s everywhere is very likely still propagating. `age_days` is
/// the age of the youngest article in the RECOVERY set, not in the
/// post - a fill can re-post par2 long after the payload.
///
/// **Nothing this returns may fail a job.** The one predicate a job can
/// be failed on is [`PostHealth::no_server_can_supply`], it reads the
/// payload fields only, and it stays that way: `post_health_fail` is
/// OFF by default as a public commitment on issue #29 (§138), and a new
/// verdict must not become a new way to end a release automatically.
/// This one badges, and it puts a clause in the failure summary of a
/// job that failed on its own.
pub(crate) fn score_recovery(
    answers: &[ServerAnswer],
    age_days: u32,
    volumes: u32,
    fetched: Option<bool>,
) -> Option<RecoveryHealth> {
    let Tally {
        sampled,
        present,
        absent,
        answered,
        servers,
        per_server,
    } = tally(answers)?;
    let unfetchable = fetched == Some(false);
    let bucket = if absent == 0 {
        if unfetchable {
            Bucket::Amber
        } else {
            Bucket::Green
        }
    } else if age_days < GONE_MIN_AGE_DAYS {
        Bucket::Amber
    } else {
        Bucket::Red
    };
    let mut reason = if absent == 0 && !unfetchable {
        format!(
            "pre-flight: the recovery set answered - all {sampled} sampled article(s) of              its {volumes} PAR2 file(s) are on at least one of {answered} server(s)"
        )
    } else if absent == 0 {
        format!(
            "pre-flight: all {sampled} sampled article(s) of the recovery set answered,              but a recovery article we asked for did not come back readable - the set              may still be fine, so this is a warning and nothing more"
        )
    } else if bucket == Bucket::Amber {
        format!(
            "pre-flight: {absent} of {sampled} sampled recovery article(s) are on none of              the {answered} server(s) that answered, but the recovery set is only              {age_days} day(s) old - it may still be propagating"
        )
    } else {
        format!(
            "pre-flight: {absent} of {sampled} sampled recovery article(s) are on none of              the {answered} server(s) that answered, and at {age_days} day(s) old the              recovery set is past the point where propagation explains it - a post whose              payload is nearly complete cannot be repaired when this is the half that is              missing"
        )
    };
    if bucket != Bucket::Green {
        reason.push_str(&format!(
            "; per server: {}",
            per_server_clause(&per_server, sampled)
        ));
    }
    if servers > answered {
        reason.push_str(&format!(
            "; {} of {servers} server(s) did not answer and were not counted",
            servers - answered
        ));
    }
    // Said out loud rather than left as a silent `None`: without it a
    // green recovery badge on a fleet of block accounts looks like the
    // stronger, body-confirmed green, and it is not.
    if fetched.is_none() {
        reason.push_str(
            "; no recovery article was fetched (no server on this install may be billed              for a measurement), so this rests on the sample alone",
        );
    }
    Some(RecoveryHealth {
        bucket,
        reason,
        sampled,
        present,
        absent,
        answered,
        servers,
        per_server,
        volumes,
        fetched,
    })
}

/// How many articles to sample for a job of `total_bytes`.
pub(crate) fn sample_size(total_bytes: u64) -> usize {
    if total_bytes >= LARGE_JOB_BYTES {
        SAMPLE_K_LARGE
    } else {
        SAMPLE_K
    }
}

/// The clause a failed job's summary gets when this job was sampled at
/// enqueue: was it already short before a byte was spent, or did it go
/// missing during the download?
///
/// That distinction is not otherwise recoverable after the fact, and it
/// is the one the user (and the indexer failure report) actually wants -
/// "the indexer handed me a dead post" and "the post rotted out from
/// under me mid-download" call for different things. `None` when the
/// sample says nothing useful about it.
pub(crate) fn failure_clause(h: &PostHealth) -> Option<String> {
    let mut out = if h.absent > 0 {
        format!(
            "; a pre-flight sample when this job was added already found {} of {} sampled \
             article(s) on none of the {} server(s) that answered, so the post was \
             short before the download started",
            h.absent, h.sampled, h.answered
        )
    } else {
        format!(
            "; a pre-flight sample when this job was added found all {} sampled \
             article(s) present, so whatever went missing did so after that",
            h.sampled
        )
    };
    // TODO §282: and the half the sentence above is silent about. On
    // the 24 Aug incident every clause up to here would have read
    // "all present" over a payload that was 99.8% intact and a recovery
    // set that could not be fetched at all - which is the one fact that
    // explains the failure, and the one nothing said.
    if let Some(r) = h.recovery.as_ref().filter(|r| r.doubtful()) {
        out.push_str(&format!(
            "; the PAR2 recovery set checked out badly too - {} of {} sampled recovery \
             article(s) were on none of the {} server(s) that answered{}, so there was \
             little repair data to be had whatever the payload was short of",
            r.absent,
            r.sampled,
            r.answered,
            if r.fetched == Some(false) {
                ", and a recovery article we asked for never came back readable"
            } else {
                ""
            }
        ));
    }
    Some(out)
}

/// TODO §138: the failure sentence for a job the opt-in give-up ends
/// before it ever starts. Only ever called on a verdict that already
/// passed [`PostHealth::no_server_can_supply`].
///
/// The opening clause is `post is gone`, which
/// [`crate::failkind::fail_kind`] classifies as [`crate::failkind::FailKind`]
/// `::Gone` - the same class a completed download that proved every
/// article absent lands in, and the class that matters here for three
/// separate reasons: it is NOT transient, so `park` arms no automatic
/// retry against a post nothing carries; it maps to NZBGet's
/// `FAILURE/HEALTH`, which is what makes the *arr blocklist the release
/// and go looking for another one instead of asking us again; and its
/// suggested action is "find another release" rather than "retry".
/// Prefix-classified, so this sentence must keep leading with it.
///
/// The rest is the evidence, in numbers the user can check: how many
/// servers, how many articles, how old. The sample size is disclosed for
/// the same reason every other surface in this module discloses it - the
/// count is never a share of the release - and the setting is named in
/// the message because a job that vanishes into history without one is
/// the single most alarming thing this feature can do.
pub(crate) fn giveup_reason(h: &PostHealth) -> String {
    format!(
        "post is gone: all {} sampled article(s) were reported missing by every one of \
         your {} configured server(s), and at {} day(s) old the post is past the point \
         where propagation explains it - failed without downloading because the \
         \"give up on posts no server can supply\" setting is on",
        h.sampled, h.servers, h.age_days
    )
}

/// §294: join the sampled loss rate against the recovery capacity the
/// NZB declares, in BYTES on both sides.
///
/// Bytes, deliberately, because it is the only unit both sides speak
/// before a download: loss is sampled in ARTICLES and repair spends
/// PAR2 BLOCKS, and the block size is unknowable until a volume has
/// been fetched and parsed - while every segment and every volume file
/// declares its bytes in the NZB. The conversion error this accepts is
/// block-boundary inflation (a lost article can invalidate two blocks
/// it straddles), and the MARGIN below is what carries it.
///
/// The interval does the honest work. `absent/sampled` from a handful
/// of STATs is a rough estimate, so the verdict uses a Wilson 95%
/// interval and takes the bound that makes each claim CONSERVATIVE:
/// `WithRecovery` requires the recovery to cover the PESSIMISTIC end
/// of the loss, and `No` requires even the OPTIMISTIC end to exceed
/// it. Everything between is `Doubtful`, which is the sample saying
/// "escalate or wait", not a hedge. On the k=8 takedown-detector
/// sample nearly every damaged post reads Doubtful - the escalated
/// sample (`tasks/health.rs`, §294) is what makes the interval narrow
/// enough to decide; the corpus test below measures exactly that.
///
/// `Yes` asks about the PAYLOAD alone: a post with no sampled loss
/// completes without repair, whatever state its recovery set is in -
/// folding a dead recovery set into "will it complete" would repeat
/// the widening mistake §282 refused.
///
/// DELIBERATELY AGE-BLIND, and the decision has been taken twice now
/// (release-eve sweep S4, settled by 99b1cd62b): the verdict "this
/// sample projects past recovery" is an honest projection at any age,
/// so this stays a pure function of the sample and the wire JSON
/// carries it unchanged. What may NOT ignore the age is any surface
/// whose COPY asserts loss - the third offer arm waits out
/// [`GONE_MIN_AGE_DAYS`] in `altcand::terminal_reason`, and the §303
/// add-dialog line keys its wording off the age-gated `bucket` that
/// rides beside this verdict. A new consumer of `No` must do the same:
/// below the propagation bar, absence is a warning and nothing more.
///
/// UNSETTLED recovery evidence must not fund a `No` (release-eve sweep
/// S4 follow-on, 25 Aug 2026). The recovery set can be much YOUNGER
/// than the payload - a fill can re-post par2 long after it
/// ([`score_recovery`]'s own age guard, and `RecoverySample.age_days`
/// exists for exactly this) - so an old damaged payload plus a
/// still-propagating fill would otherwise read `rec_frac ~ 0` and
/// verdict `No` on articles nobody can fetch YET. A young-and-absent
/// sample is epistemically the same state as an unprobed set, which is
/// already taken at face value: "we cannot yet say the declared bytes
/// are not there". The face value applies to the `No` decision ONLY,
/// and asymmetrically on purpose - PROMISING `WithRecovery` off
/// recovery articles nobody can fetch yet would be the opposite
/// overclaim - so when the discounted bytes read short but the
/// face-value bytes would cover the optimistic ask, the honest verdict
/// is `Doubtful`. When even face value cannot cover it, `No` stands:
/// the declaration itself is too small, and no amount of settling
/// fixes that. The state is read off the bucket rather than a fresh
/// age parameter because with `absent > 0` Amber IS "young"
/// ([`score_recovery`]'s `unfetchable` route to Amber requires
/// `absent == 0`), and the bucket was scored from the RECOVERY set's
/// own age - the payload age gate on the offer (altcand.rs, S4) is a
/// different guard on a different sample's age.
pub(crate) fn score_completable(
    payload: &PostHealth,
    rec: Option<&RecoveryHealth>,
    payload_bytes: u64,
    recovery_bytes: u64,
) -> Completable {
    if payload.sampled == 0 || payload_bytes == 0 {
        return Completable::Doubtful;
    }
    if payload.absent == 0 {
        return Completable::Yes;
    }
    let (lo, hi) = wilson_bounds(payload.absent, payload.sampled);
    // What the recovery set can actually fund: the declared volume
    // bytes, scaled by the fraction of the RECOVERY sample that is
    // still present (its own loss rate - §282's incident is precisely
    // recovery that exists on paper and not on the wire), and by the
    // packet-overhead haircut. An unprobed recovery set is taken at
    // face value; `WithRecovery` then rests on the declaration, which
    // is what the pre-§294 reader assumed implicitly anyway.
    let rec_frac = match rec {
        Some(r) if r.sampled > 0 => f64::from(r.present) / f64::from(r.sampled),
        _ => 1.0,
    };
    // ~68 bytes of packet framing per slice plus the duplicated
    // critical packets: 0.9 is deliberately a haircut, not a model.
    let usable = recovery_bytes as f64 * rec_frac * 0.9;
    // Block-boundary inflation: a lost article invalidates every block
    // it touches, so the pessimistic ask is padded before recovery may
    // promise to cover it.
    let need_hi = hi * payload_bytes as f64 * 1.2;
    let need_lo = lo * payload_bytes as f64;
    if usable >= need_hi {
        Completable::WithRecovery
    } else if usable < need_lo {
        // The S4 follow-on guard from the header: a young recovery
        // set's absent articles may simply not have propagated, so
        // before the discount is allowed to conclude `No`, ask whether
        // the DECLARED bytes at face value would still fall short. Only
        // the `No` arm - face value never promises `WithRecovery`.
        let unsettled = rec.is_some_and(|r| r.absent > 0 && r.bucket == Bucket::Amber);
        if unsettled && recovery_bytes as f64 * 0.9 >= need_lo {
            Completable::Doubtful
        } else {
            Completable::No
        }
    } else {
        Completable::Doubtful
    }
}

/// Wilson 95% interval on a sampled proportion - the standard score
/// interval, which stays honest at the tiny n this module lives at
/// (a normal approximation puts negative loss on 0-of-8).
fn wilson_bounds(hits: u32, n: u32) -> (f64, f64) {
    let z = 1.96f64;
    let n = f64::from(n);
    let p = f64::from(hits) / n;
    let z2 = z * z;
    let denom = 1.0 + z2 / n;
    let center = (p + z2 / (2.0 * n)) / denom;
    let half = z * (p * (1.0 - p) / n + z2 / (4.0 * n * n)).sqrt() / denom;
    ((center - half).max(0.0), (center + half).min(1.0))
}

pub(crate) fn health_json(h: &PostHealth) -> serde_json::Value {
    serde_json::json!({
        "bucket": h.bucket.as_str(),
        "reason": h.reason,
        "per_server": h.per_server
            .iter()
            .map(|(host, have, missing)| serde_json::json!({
                "host": host, "have": have, "missing": missing,
            }))
            .collect::<Vec<_>>(),
        "sampled": h.sampled,
        "present": h.present,
        "absent": h.absent,
        "answered": h.answered,
        "servers": h.servers,
        "age_days": h.age_days,
        "checked_at": h.checked_at,
        "probes": h.probes,
        "waived": h.waived,
        // §294: absent entirely when never computed, so a pre-293
        // record round-trips byte-identical.
        "completable": h.completable.map(Completable::as_str),
        // §282: nested rather than flattened, so no consumer of the
        // payload keys can pick a recovery number up by accident.
        "recovery": h.recovery.as_ref().map(|r| serde_json::json!({
            "bucket": r.bucket.as_str(),
            "reason": r.reason,
            "per_server": r.per_server
                .iter()
                .map(|(host, have, missing)| serde_json::json!({
                    "host": host, "have": have, "missing": missing,
                }))
                .collect::<Vec<_>>(),
            "sampled": r.sampled,
            "present": r.present,
            "absent": r.absent,
            "answered": r.answered,
            "servers": r.servers,
            "volumes": r.volumes,
            "fetched": r.fetched,
        })),
    })
}

/// The per-server census, back off the wire. Shared by both halves of
/// [`health_from_json`] because the shape is the same on both.
fn per_server_from_json(v: &serde_json::Value) -> Vec<(String, u32, u32)> {
    v.get("per_server")
        .and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|e| {
                    Some((
                        e.get("host")?.as_str()?.to_string(),
                        e.get("have")?.as_u64()? as u32,
                        e.get("missing")?.as_u64()? as u32,
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// One recovery verdict, back off the wire. `None` for an absent or
/// unreadable record - a job persisted before §282 has no such key and
/// must load exactly as it did.
fn recovery_from_json(v: &serde_json::Value) -> Option<RecoveryHealth> {
    let u = |k: &str| v.get(k).and_then(serde_json::Value::as_u64).unwrap_or(0) as u32;
    Some(RecoveryHealth {
        bucket: Bucket::from_str(v.get("bucket").and_then(serde_json::Value::as_str)?)?,
        reason: v
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        per_server: per_server_from_json(v),
        sampled: u("sampled"),
        present: u("present"),
        absent: u("absent"),
        answered: u("answered"),
        servers: u("servers"),
        volumes: u("volumes"),
        fetched: v.get("fetched").and_then(serde_json::Value::as_bool),
    })
}

pub(crate) fn health_from_json(v: &serde_json::Value) -> Option<PostHealth> {
    let u = |k: &str| v.get(k).and_then(serde_json::Value::as_u64).unwrap_or(0) as u32;
    Some(PostHealth {
        bucket: Bucket::from_str(v.get("bucket").and_then(serde_json::Value::as_str)?)?,
        reason: v
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        per_server: per_server_from_json(v),
        sampled: u("sampled"),
        present: u("present"),
        absent: u("absent"),
        answered: u("answered"),
        servers: u("servers"),
        age_days: u("age_days"),
        checked_at: v
            .get("checked_at")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0),
        probes: u("probes").max(1),
        waived: v
            .get("waived")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        recovery: v.get("recovery").and_then(recovery_from_json),
        completable: v
            .get("completable")
            .and_then(serde_json::Value::as_str)
            .and_then(Completable::from_str),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(host: &str, cells: &[Avail]) -> ServerAnswer {
        ServerAnswer {
            host: host.into(),
            cells: cells.to_vec(),
        }
    }

    const H: Avail = Avail::Have;
    const M: Avail = Avail::Missing;
    const U: Avail = Avail::Unknown;

    #[test]
    fn everything_present_is_green() {
        let s = score(
            &[answer("a", &[H, H, H]), answer("b", &[H, M, H])],
            400,
            0,
            1,
        )
        .unwrap();
        assert_eq!(s.bucket, Bucket::Green);
        assert_eq!((s.present, s.absent, s.sampled), (3, 0, 3));
        // One server missing an article it simply does not carry says
        // nothing: the other one has it, so the download completes.
        assert_eq!(s.answered, 2);
    }

    /// The binding constraint, as a test. A post that 430s on EVERY
    /// server is amber - not red - while it is young enough for
    /// propagation to be the explanation. This is the trap that has been
    /// walked into twice (memory `nzbfast-retry-propagation-trap`).
    #[test]
    fn a_young_post_missing_everywhere_is_amber_not_red() {
        for age in 0..GONE_MIN_AGE_DAYS {
            let s = score(&[answer("a", &[M, M]), answer("b", &[M, M])], age, 0, 1).unwrap();
            assert_eq!(s.bucket, Bucket::Amber, "age {age}");
            assert!(!s.sinks(), "an amber must never sink the job");
        }
        let old = score(
            &[answer("a", &[M, M]), answer("b", &[M, M])],
            GONE_MIN_AGE_DAYS,
            0,
            1,
        )
        .unwrap();
        assert_eq!(old.bucket, Bucket::Red);
        assert!(old.sinks());
    }

    /// A dateless NZB reads as age 0, and age 0 is FRESH. Same rule as
    /// `nzb_age_days` and the "gone" verdict: unknown is not old.
    #[test]
    fn a_dateless_post_is_never_red() {
        let s = score(&[answer("a", &[M, M, M])], 0, 0, 1).unwrap();
        assert_eq!(s.bucket, Bucket::Amber);
    }

    /// A server that never answered is not a vote in either direction.
    /// Without this, one host with a bad password makes every post in
    /// the queue read green (its Unknown blocks every union), which is
    /// exactly the reassurance the feature must not give.
    #[test]
    fn a_silent_server_is_dropped_not_counted() {
        let s = score(
            &[answer("dead", &[U, U, U]), answer("live", &[M, M, M])],
            30,
            0,
            1,
        )
        .unwrap();
        assert_eq!(s.bucket, Bucket::Red);
        assert_eq!((s.answered, s.servers), (1, 2));
        assert!(s.reason.contains("1 of 2 server(s) did not answer"));
    }

    /// An Unknown cell inside a server that DID answer still blocks that
    /// article: a session that died mid-pipeline knows nothing about the
    /// ids it never reached, and a miss must never be manufactured.
    #[test]
    fn a_half_answered_server_blocks_only_its_own_gaps() {
        let s = score(
            &[answer("a", &[M, U, M]), answer("b", &[M, M, U])],
            30,
            0,
            1,
        )
        .unwrap();
        // Article 0 is missing on both; 1 and 2 each have an Unknown.
        assert_eq!((s.absent, s.present), (1, 2));
        assert_eq!(s.bucket, Bucket::Red);
    }

    #[test]
    fn no_evidence_scores_nothing() {
        assert!(score(&[], 30, 0, 1).is_none());
        assert!(score(&[answer("a", &[U, U])], 30, 0, 1).is_none());
        assert!(score(&[answer("a", &[])], 30, 0, 1).is_none());
    }

    /// An abandoned probe - timeout, stand-down, mid-batch error - leaves
    /// the unread tail Unknown, and ONE definite Have used to qualify the
    /// row as voting and score Green: "all 8 sampled article(s) present"
    /// with seven never asked. No definite answer for a cell on any
    /// server plus no miss anywhere = nothing learned, no verdict.
    #[test]
    fn a_cut_short_probe_with_no_misses_scores_nothing() {
        // 1 of 8 read, a Have, the rest Unknown on the only server.
        assert!(score(&[answer("a", &[H, U, U, U, U, U, U, U])], 30, 0, 1).is_none());
        // Same rows across two servers, both cut short at the same spot.
        assert!(
            score(
                &[answer("a", &[H, H, U, U]), answer("b", &[H, U, U, U])],
                30,
                0,
                1
            )
            .is_none()
        );
        // A definite MISS elsewhere is still evidence, however short the
        // probe fell: this one buckets normally (30 days is past
        // GONE_MIN_AGE_DAYS, so red).
        let s = score(&[answer("a", &[M, H, U, U])], 30, 0, 1).unwrap();
        assert_eq!(s.bucket, Bucket::Red);
        // And a fully-answered green is untouched.
        let s = score(&[answer("a", &[H, H, H, H])], 30, 0, 1).unwrap();
        assert_eq!(s.bucket, Bucket::Green);
    }

    /// The sampled count rides every verdict, and none of them phrases
    /// itself as a share of the release.
    #[test]
    fn the_reason_always_discloses_the_sample() {
        for (cells, age) in [(vec![H, H], 30u32), (vec![M, H], 1), (vec![M, M], 30)] {
            let s = score(&[answer("a", &cells)], age, 0, 1).unwrap();
            assert!(s.reason.contains("sampled article(s)"), "{}", s.reason);
            assert!(!s.reason.contains('%'), "{}", s.reason);
        }
    }

    #[test]
    fn large_jobs_sample_wider() {
        assert_eq!(sample_size(0), SAMPLE_K);
        assert_eq!(sample_size(LARGE_JOB_BYTES - 1), SAMPLE_K);
        assert_eq!(sample_size(LARGE_JOB_BYTES), SAMPLE_K_LARGE);
    }

    /// TODO §138. The bar the opt-in give-up needs, one clause at a
    /// time. Everything here except the first case is a verdict the
    /// AMBER-vs-red reorder is perfectly happy to act on, and none of
    /// them may end a release.
    #[test]
    fn only_a_unanimous_fully_missing_sample_can_give_up() {
        // Every configured server, every sampled article, past the
        // propagation age. The one shape that qualifies.
        let all = score(
            &[answer("a", &[M, M, M]), answer("b", &[M, M, M])],
            30,
            0,
            1,
        )
        .unwrap();
        assert!(all.no_server_can_supply());
        assert_eq!(
            (all.answered, all.servers, all.absent, all.sampled),
            (2, 2, 3, 3)
        );

        // THE discriminating case: one server confirms the articles
        // missing, the other never answered at all. Red (the silent host
        // is dropped from the verdict), so the reorder still sinks it -
        // and it must never be failed, because the fleet has not spoken.
        let silent = score(
            &[answer("a", &[M, M, M]), answer("dead", &[U, U, U])],
            30,
            0,
            1,
        )
        .unwrap();
        assert_eq!(silent.bucket, Bucket::Red);
        assert!(silent.sinks());
        assert!(
            !silent.no_server_can_supply(),
            "a server that never answered cannot be part of a unanimous verdict"
        );

        // Short, not gone. Two of three missing everywhere is what PAR2
        // exists for, and a sample of three cannot say otherwise.
        let short = score(
            &[answer("a", &[M, M, H]), answer("b", &[M, M, H])],
            30,
            0,
            1,
        )
        .unwrap();
        assert_eq!(short.bucket, Bucket::Red);
        assert!(!short.no_server_can_supply());

        // An Unknown cell inside a server that DID answer is still a
        // hole in the evidence: that article was never asked of it.
        let ragged = score(
            &[answer("a", &[M, M, U]), answer("b", &[M, M, M])],
            30,
            0,
            1,
        )
        .unwrap();
        assert_eq!(ragged.bucket, Bucket::Red);
        assert!(!ragged.no_server_can_supply());

        // Young enough for propagation to explain it: amber, and amber
        // never reaches the bar however unanimous it is.
        for age in 0..GONE_MIN_AGE_DAYS {
            let young = score(&[answer("a", &[M, M]), answer("b", &[M, M])], age, 0, 1).unwrap();
            assert_eq!(young.bucket, Bucket::Amber, "age {age}");
            assert!(!young.no_server_can_supply(), "age {age}");
        }

        // Green is green.
        assert!(
            !score(&[answer("a", &[H, H])], 30, 0, 1)
                .unwrap()
                .no_server_can_supply()
        );
    }

    /// A waiver is the user saying they want this job. The reorder drops
    /// its scheduling effect for one, and the much heavier give-up owes
    /// it at least the same deference.
    #[test]
    fn a_waived_verdict_never_gives_up() {
        let mut s = score(&[answer("a", &[M, M])], 30, 0, 1).unwrap();
        assert!(s.no_server_can_supply());
        s.waived = true;
        assert!(!s.no_server_can_supply());
        assert!(!s.sinks());
    }

    /// The give-up sentence has to keep leading with `post is gone`:
    /// `fail_kind` classifies on the OPENING, and the whole point of the
    /// feature is the `Gone` class - no auto-retry, FAILURE/HEALTH to
    /// the *arr, "find another release" as the suggested move.
    #[test]
    fn the_giveup_sentence_is_classified_gone_and_shows_its_evidence() {
        let s = score(&[answer("a", &[M, M]), answer("b", &[M, M])], 41, 0, 1).unwrap();
        let msg = giveup_reason(&s);
        assert!(msg.starts_with("post is gone"), "{msg}");
        assert!(msg.contains("all 2 sampled article(s)"), "{msg}");
        assert!(msg.contains("your 2 configured server(s)"), "{msg}");
        assert!(msg.contains("41 day(s) old"), "{msg}");
        // Never a share of the release, same rule as every other surface.
        assert!(!msg.contains('%'), "{msg}");
        // The setting is named: a job that ends up in history without a
        // byte spent must say what decided that.
        assert!(
            msg.contains("give up on posts no server can supply"),
            "{msg}"
        );
    }

    #[test]
    fn json_round_trips() {
        let s = score(
            &[answer("a", &[M, H]), answer("b", &[M, H])],
            9,
            1_700_000_000,
            2,
        )
        .unwrap();
        assert_eq!(health_from_json(&health_json(&s)), Some(s));
    }

    /// A record written by an older build (or hand-edited) must not
    /// resurrect as a bogus verdict.
    #[test]
    fn an_unreadable_record_is_no_verdict() {
        assert!(health_from_json(&serde_json::json!({})).is_none());
        assert!(health_from_json(&serde_json::json!({"bucket": "puce"})).is_none());
    }

    #[test]
    fn the_failure_clause_tells_before_from_during() {
        let short = score(&[answer("a", &[M, H])], 30, 0, 1).unwrap();
        assert!(
            failure_clause(&short)
                .unwrap()
                .contains("short before the download started")
        );
        let clean = score(&[answer("a", &[H, H])], 30, 0, 1).unwrap();
        assert!(
            failure_clause(&clean)
                .unwrap()
                .contains("went missing did so after that")
        );
    }

    // -----------------------------------------------------------------
    // TODO §282 items 1 and 2: the recovery set's own verdict.
    // -----------------------------------------------------------------

    /// The incident, in one assertion. The payload samples clean and
    /// the recovery set does not, and the two verdicts must be able to
    /// disagree: a job whose payload is 99.8% intact and whose PAR2 is
    /// unobtainable is exactly the 24 Aug shape, and it badged green.
    #[test]
    fn the_recovery_verdict_is_scored_apart_from_the_payload() {
        let payload = score(&[answer("a", &[H, H, H])], 400, 0, 1).unwrap();
        assert_eq!(payload.bucket, Bucket::Green);
        let rec = score_recovery(&[answer("a", &[M, M, M])], 400, 9, Some(false)).unwrap();
        assert_eq!(rec.bucket, Bucket::Red);
        assert_eq!((rec.absent, rec.sampled), (3, 3));
        assert_eq!(rec.volumes, 9);
        assert!(rec.doubtful());
        // And the payload buckets are untouched by it: nothing here may
        // widen what `absent`/`present` mean, because the amber
        // propagation guard and the §138 give-up read them.
        assert_eq!((payload.absent, payload.present), (0, 3));
    }

    /// The propagation guard is the same guard here, and it runs on the
    /// RECOVERY set's own age. Below [`GONE_MIN_AGE_DAYS`] a recovery
    /// set missing everywhere is still amber - it may be landing.
    #[test]
    fn a_young_recovery_set_missing_everywhere_is_only_amber() {
        let r = score_recovery(&[answer("a", &[M, M])], 1, 3, None).unwrap();
        assert_eq!(r.bucket, Bucket::Amber);
        let old = score_recovery(&[answer("a", &[M, M])], 30, 3, None).unwrap();
        assert_eq!(old.bucket, Bucket::Red);
    }

    /// A failed BODY fetch on its own can only reach AMBER, however old
    /// the post. `probe_recovery_set` answers `None` for a refused
    /// article and for a set whose Main packet simply was not in the two
    /// articles it drew, and it cannot say which - so on a clean STAT
    /// sample it is a warning, never proof. It must still stop the row
    /// badging green, which is the whole point of the item.
    #[test]
    fn an_unfetchable_set_that_stats_clean_is_amber_and_never_red() {
        let r = score_recovery(&[answer("a", &[H, H])], 4000, 2, Some(false)).unwrap();
        assert_eq!(r.bucket, Bucket::Amber);
        assert!(r.doubtful(), "the row must stop badging green");
        assert_eq!(r.absent, 0);
        // Confirmed by the bytes is the strong green; a skipped fetch is
        // still green but says so.
        let strong = score_recovery(&[answer("a", &[H, H])], 4000, 2, Some(true)).unwrap();
        assert_eq!(strong.bucket, Bucket::Green);
        assert!(!strong.reason.contains("no recovery article was fetched"));
        let unpaid = score_recovery(&[answer("a", &[H, H])], 4000, 2, None).unwrap();
        assert_eq!(unpaid.bucket, Bucket::Green);
        assert!(unpaid.reason.contains("no recovery article was fetched"));
    }

    /// A host that never answered is dropped from THIS verdict too. One
    /// server with a wrong password must not paint every recovery set in
    /// the queue green - the trap `score` unions for itself to avoid,
    /// and the reason both share [`tally`].
    #[test]
    fn a_silent_server_is_dropped_from_the_recovery_verdict() {
        let r = score_recovery(
            &[answer("a", &[M, M]), answer("mute", &[U, U])],
            30,
            4,
            None,
        )
        .unwrap();
        assert_eq!(r.bucket, Bucket::Red, "the silent host is not a vote");
        assert_eq!((r.answered, r.servers), (1, 2));
        assert!(r.reason.contains("did not answer and were not counted"));
        // Nothing answered at all: no verdict, not a green one.
        assert!(score_recovery(&[answer("mute", &[U, U])], 30, 4, None).is_none());
        assert!(score_recovery(&[], 30, 4, Some(false)).is_none());
    }

    /// It survives the wire and a restart, and a record written before
    /// §282 loads exactly as it did.
    #[test]
    fn the_recovery_verdict_round_trips_and_older_records_still_load() {
        let mut h = score(&[answer("a", &[H, M])], 30, 99, 1).unwrap();
        h.recovery = score_recovery(&[answer("a", &[M, H])], 30, 7, Some(false));
        let back = health_from_json(&health_json(&h)).unwrap();
        assert_eq!(back, h);
        let r = back.recovery.unwrap();
        assert_eq!(r.fetched, Some(false));
        assert_eq!(r.volumes, 7);
        assert_eq!(r.per_server, vec![("a".to_string(), 1, 1)]);

        let mut old = health_json(&score(&[answer("a", &[H, H])], 30, 99, 1).unwrap());
        old.as_object_mut().unwrap().remove("recovery");
        assert!(health_from_json(&old).unwrap().recovery.is_none());
    }

    /// The failure summary carries it. On the incident every clause the
    /// old code could write said "all present" - true of the payload,
    /// and silent about the half that killed the job.
    #[test]
    fn the_failure_clause_names_the_recovery_set() {
        let mut clean = score(&[answer("a", &[H, H])], 30, 0, 1).unwrap();
        clean.recovery = score_recovery(&[answer("a", &[M, M])], 30, 5, Some(false));
        let c = failure_clause(&clean).unwrap();
        assert!(c.contains("went missing did so after that"), "{c}");
        assert!(c.contains("PAR2 recovery set checked out badly"), "{c}");
        assert!(c.contains("never came back readable"), "{c}");
        // A green recovery set adds nothing: the quiet case stays quiet.
        let mut fine = score(&[answer("a", &[H, H])], 30, 0, 1).unwrap();
        fine.recovery = score_recovery(&[answer("a", &[H, H])], 30, 5, Some(true));
        assert!(!failure_clause(&fine).unwrap().contains("recovery set"));
    }

    /// The one predicate a job can be FAILED on stays payload-only.
    /// `post_health_fail` is off by default as a public commitment on
    /// issue #29 (§138), and a new verdict must not become a new way to
    /// end a release automatically.
    #[test]
    fn a_dead_recovery_set_never_licenses_the_optin_giveup() {
        let mut h = score(&[answer("a", &[H, H])], 400, 0, 1).unwrap();
        h.recovery = score_recovery(&[answer("a", &[M, M])], 400, 5, Some(false));
        assert_eq!(h.recovery.as_ref().unwrap().bucket, Bucket::Red);
        assert!(
            !h.no_server_can_supply(),
            "the recovery verdict must not reach the give-up bar"
        );
        assert!(!h.sinks(), "nor the auto-defer");
    }

    /// A payload verdict carrying exactly these counts, for driving
    /// `score_completable` without staging a STAT matrix.
    fn ph(absent: u32, sampled: u32) -> PostHealth {
        PostHealth {
            bucket: if absent == 0 {
                Bucket::Green
            } else {
                Bucket::Red
            },
            reason: String::new(),
            per_server: Vec::new(),
            sampled,
            present: sampled - absent,
            absent,
            answered: 1,
            servers: 1,
            age_days: 30,
            checked_at: 0,
            probes: 1,
            waived: false,
            recovery: None,
            completable: None,
        }
    }

    /// §294's fixed points: no sampled loss is Yes whatever the
    /// recovery set looks like, total loss with a thin recovery set is
    /// No even at the optimistic bound, and an empty sample decides
    /// nothing.
    #[test]
    fn completable_fixed_points() {
        let gb = 1_000_000_000u64;
        assert_eq!(
            score_completable(&ph(0, 64), None, 50 * gb, 0),
            Completable::Yes
        );
        assert_eq!(
            score_completable(&ph(0, 0), None, 50 * gb, gb),
            Completable::Doubtful
        );
        assert_eq!(
            score_completable(&ph(64, 64), None, 50 * gb, 2 * gb),
            Completable::No,
            "an all-missing sample against 4% recovery is short at ANY bound"
        );
        assert_eq!(
            score_completable(&ph(1, 64), None, 50 * gb, 10 * gb),
            Completable::WithRecovery,
            "~1.6% sampled loss under 20% declared recovery is covered even \
             pessimistically (the Wilson upper bound on 1-of-64 is ~8%)"
        );
        // The §282 shape: recovery that exists on paper and not on the
        // wire. The same damage flips from covered to No when the
        // recovery sample reports the set absent.
        let dead_rec = RecoveryHealth {
            bucket: Bucket::Red,
            reason: String::new(),
            per_server: Vec::new(),
            sampled: 8,
            present: 0,
            absent: 8,
            answered: 1,
            servers: 1,
            volumes: 5,
            fetched: Some(false),
        };
        assert_eq!(
            score_completable(&ph(4, 64), Some(&dead_rec), 50 * gb, 5 * gb),
            Completable::No,
            "declared recovery scaled by a dead recovery sample funds nothing"
        );
    }

    /// The verdict is deliberately age-blind (see [`score_completable`]'s
    /// doc): identical evidence scores `No` at any age, and the AGE
    /// discipline lives on the surfaces - `altcand::terminal_reason`
    /// waits out the propagation window before offering, and the §303
    /// add dialog keys its wording off the age-gated bucket. This pins
    /// the purity so a re-derived in-verdict guard (tried 25 Aug 2026,
    /// reverted for 99b1cd62b's arm-level design) does not quietly come
    /// back and break the wire the offer tests stand on.
    #[test]
    fn completable_is_age_blind_by_design() {
        let gb = 1_000_000_000u64;
        let mut young = ph(64, 64);
        young.age_days = 0;
        young.bucket = Bucket::Amber;
        assert_eq!(
            score_completable(&young, None, 50 * gb, 2 * gb),
            Completable::No,
            "the projection is the same statement at any age; the offer \
             arm, not this function, waits out propagation"
        );
    }

    /// The S4 follow-on (§294): UNSETTLED recovery evidence must not
    /// fund a `No`. The fixtures go through [`score_recovery`] rather
    /// than a hand-built struct so the young-and-absent state stays
    /// what the prober actually lands (Amber with `absent > 0` IS the
    /// young state - the `unfetchable` route to Amber requires
    /// `absent == 0`, and the last case pins that conjunction).
    ///
    /// The payload throughout is 4-of-64 absent over 50 GB: the Wilson
    /// optimistic ask (`need_lo`) is ~1.23 GB, the pessimistic one
    /// (`need_hi`) ~9 GB.
    #[test]
    fn a_young_absent_recovery_sample_cannot_fund_a_no() {
        let gb = 1_000_000_000u64;
        // Still-propagating fill, sampled all-absent. 5 GB declared
        // covers the optimistic ask at face value, so the discount may
        // not conclude `No` - and the interval genuinely cannot tell,
        // so `Doubtful` is the honest verdict, not a suppression.
        let young_dead = score_recovery(&[answer("a", &[M, M])], 1, 5, None).unwrap();
        assert_eq!(young_dead.bucket, Bucket::Amber);
        assert_eq!(
            score_completable(&ph(4, 64), Some(&young_dead), 50 * gb, 5 * gb),
            Completable::Doubtful,
            "a still-propagating recovery sample is not evidence the declared bytes are gone"
        );
        // Face value refuses the `No` and never promises the opposite:
        // 20 GB declared covers even the pessimistic ask at face value,
        // and the verdict must still be Doubtful, not WithRecovery -
        // repair may not be PROMISED off articles nobody can fetch yet.
        let young_thin = score_recovery(
            &[answer(
                "a",
                &[H, M, M, M, M, M, M, M, M, M, M, M, M, M, M, M],
            )],
            1,
            5,
            None,
        )
        .unwrap();
        assert_eq!(young_thin.bucket, Bucket::Amber);
        assert_eq!(
            score_completable(&ph(4, 64), Some(&young_thin), 50 * gb, 20 * gb),
            Completable::Doubtful,
            "face value funds only the refusal of No, never a WithRecovery"
        );
        // A declaration too small to cover even the optimistic ask is
        // `No` at ANY age - settling cannot grow the declared bytes.
        // This is the case a bare suppress-when-young gate gets wrong,
        // and why the guard recomputes at face value instead.
        assert_eq!(
            score_completable(&ph(4, 64), Some(&young_dead), 50 * gb, gb),
            Completable::No,
            "0.9 GB usable against a ~1.23 GB optimistic ask: the declaration itself is short"
        );
        // The same shapes SETTLED (past the propagation window, Red):
        // the §282 verdict stands byte-identical - absent evidence that
        // propagation no longer excuses funds nothing.
        let old_dead = score_recovery(&[answer("a", &[M, M])], 400, 5, None).unwrap();
        assert_eq!(old_dead.bucket, Bucket::Red);
        assert_eq!(
            score_completable(&ph(4, 64), Some(&old_dead), 50 * gb, 5 * gb),
            Completable::No,
            "an OLD absent recovery sample keeps funding the No"
        );
        // And Amber reached the OTHER way - `unfetchable`, absent == 0 -
        // is not the young-absent state: rec_frac is already 1.0 there,
        // so the guard must not engage and the plain verdict stands.
        let unfetchable = score_recovery(&[answer("a", &[H, H])], 400, 5, Some(false)).unwrap();
        assert_eq!((unfetchable.bucket, unfetchable.absent), (Bucket::Amber, 0));
        assert_eq!(
            score_completable(&ph(4, 64), Some(&unfetchable), 50 * gb, gb),
            Completable::No,
        );
    }

    /// §294's A/B, measured over a corpus: the same damaged posts
    /// judged from the k=8 takedown-detector sample and from the k=64
    /// escalated sample. Ground truth per scenario is the exact
    /// arithmetic (missing bytes vs what the recovery slices can fund
    /// at PAR2's ~0.95 slice efficiency); the sample is a seeded
    /// binomial draw, so the numbers are reproducible.
    ///
    /// A decision is CORRECT when it matches the truth (`No` on a
    /// doomed post; `Yes`/`WithRecovery` on a repairable one), WRONG
    /// when it contradicts it, and `Doubtful` is undecided. The first
    /// cut of this test asserted "never a false kill" and the corpus
    /// refuted it in one run: `No` rests on a 95% interval, so ~2% of
    /// repairable draws at k=8 clear even the optimistic bound (13 of
    /// 1000 measured; 1 of 1000 at k=64). That is what a confidence
    /// bound MEANS, and the honest claims - the ones this asserts -
    /// are that escalation multiplies doomed catches, collapses wrong
    /// calls, and keeps the false-kill rate inside the interval's own
    /// tail. What it does NOT claim, because the corpus refuted that
    /// too: a higher overall correct count. At k=8 a low-loss post
    /// often samples clean and reads a lucky, unfounded `Yes` that
    /// happens to be right; k=64 sees the loss and answers `Doubtful`.
    /// Escalation converts confident guessing into honest indecision,
    /// and that conversion is a cost worth naming, not hiding.
    /// Measured on this seed: k=8 is 909 correct / 394 wrong / 697
    /// undecided with 263/1000 doomed caught and 13 false kills; k=64
    /// is 879 / 8 / 1113 with 607/1000 caught and 1 false kill.
    #[test]
    fn the_escalated_sample_separates_repairable_from_short() {
        let mut s = 0x9E37_79B9_7F4A_7C15u64;
        let mut rng = move || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        let payload = 50_000_000_000u64;
        let trials = 200u32;
        // (true loss rate, declared recovery as a fraction of payload)
        let corpus: &[(f64, f64)] = &[
            (0.02, 0.05),
            (0.02, 0.15),
            (0.05, 0.02),
            (0.05, 0.10),
            (0.08, 0.05),
            (0.08, 0.15),
            (0.12, 0.05),
            (0.12, 0.20),
            (0.20, 0.10),
            (0.35, 0.10),
        ];
        // [leg] -> (correct, wrong, undecided, doomed caught,
        //           doomed total, false kills, repairable total)
        let mut tally = [[0u64; 7]; 2];
        for &(p, r) in corpus {
            let recovery = (r * payload as f64) as u64;
            let doomed = p * payload as f64 > recovery as f64 * 0.95;
            for _ in 0..trials {
                for (leg, k) in [(0usize, 8u32), (1, 64)] {
                    let mut absent = 0u32;
                    for _ in 0..k {
                        // 53 uniform bits against the true loss rate.
                        if ((rng() >> 11) as f64 / (1u64 << 53) as f64) < p {
                            absent += 1;
                        }
                    }
                    let v = score_completable(&ph(absent, k), None, payload, recovery);
                    let t = &mut tally[leg];
                    match v {
                        Completable::Doubtful => t[2] += 1,
                        Completable::No if doomed => t[0] += 1,
                        Completable::No => t[1] += 1,
                        _ if doomed => t[1] += 1,
                        _ => t[0] += 1,
                    }
                    if doomed {
                        t[4] += 1;
                        if v == Completable::No {
                            t[3] += 1;
                        }
                    } else {
                        t[6] += 1;
                        if v == Completable::No {
                            t[5] += 1;
                        }
                    }
                }
            }
        }
        for (leg, k) in [(0usize, 8), (1, 64)] {
            let t = &tally[leg];
            println!(
                "§294 A/B k={k}: correct {} / wrong {} / undecided {} \
                 (doomed caught {}/{}, false kills {}/{})",
                t[0], t[1], t[2], t[3], t[4], t[5], t[6]
            );
        }
        assert!(
            tally[1][3] > tally[0][3],
            "the escalated sample catches more doomed posts: {} vs {}",
            tally[1][3],
            tally[0][3]
        );
        assert!(
            tally[1][1] < tally[0][1],
            "and makes fewer wrong calls: {} vs {}",
            tally[1][1],
            tally[0][1]
        );
        // No is a 95%-confidence claim, and the false-kill rate must
        // stay inside that claim's own tail at the escalated k.
        assert!(
            (tally[1][5] as f64) <= tally[1][6] as f64 * 0.025,
            "k=64 false kills outside the interval's tail: {}/{}",
            tally[1][5],
            tally[1][6]
        );
    }
}
