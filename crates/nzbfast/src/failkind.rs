//! How a failure MESSAGE is classified, and what the page says about it.
//!
//! `FailKind` over the terminal message, the hint and the action
//! rendered from it, and the two disk-full predicates. Everything here
//! takes a `&str` and answers a small value: there is no `Job`, no
//! `Daemon` and no database, which is exactly why it lives at the crate
//! root rather than under `serve/`.
//!
//! It sat in `serve/job_fail.rs` until TODO 276 item 3, and that was
//! the single largest back-edge in the crate: `crate::diag` reaches
//! `fail_kind` and three `FailKind` variants eighteen times, which put
//! `diag` - and through it everything `diag` touches - inside the
//! 28-module dependency cycle `serve` sits in. Classification is not a
//! daemon concern and never was. `serve/job_fail.rs` keeps the half
//! that IS one: the post-job duties, the auto-retry policy and the
//! notify-token merge, all of which take a `&Job`.
//!
//! `serve::job` re-exports these names, so every caller inside `serve`
//! still spells them the way it always did.
//!
//! TODO 307 item 1 added [`fail_kind_of`] beside [`fail_kind`]: where a
//! caller holds `nzbkit`'s typed [`FailCode`], that decides and the
//! sentence is never consulted. The string classifier stays under it
//! because it is still the arm in use for a job's terminal failure -
//! see [`fail_kind_of`] for exactly what does and does not carry a code
//! today, and `failkind::tests` for the matrix that pins both.

use nzbkit::fail::FailCode;

/// Why a job failed, as far as the two policies that care are concerned:
/// the auto-retry cooldown (`park`) and the dead-post report
/// (`report_failure`). One classifier so they cannot drift apart - they
/// already had, and a disk-full run was both auto-retried onto the same
/// full disk AND reported to the indexer as a dead post.
///
/// Re-derivable from `fail_message`, and since TODO 307 item 1's
/// job-level carry also STATED by the producer and stored on the job as
/// [`Job::fail_code`](crate::serve::job::Job) - see [`job_kind`] for
/// which of the two answers, and why the older reading of this paragraph
/// ("a field would be this same match written one layer earlier plus a
/// second thing to keep in step with the sentence") was half right: it
/// IS a second thing to keep in step, and what keeps it in step is a
/// test that drives both off one producer call rather than a hope.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum FailKind {
    /// Articles were missing from every server that has the post.
    MissingArticles,
    /// Every lost segment was a TRANSPORT failure - timeouts, resets,
    /// nonstandard responses, retry budgets exhausted - and no server
    /// ever said 430. Says nothing about the post's health, so it must
    /// NOT be reported to an indexer as a dead post (a flaky provider
    /// under load used to file takedown reports for perfectly healthy
    /// releases). Retrying can absolutely fix it.
    Transport,
    /// The bytes arrived but PAR2 could not make them whole.
    Unrepairable,
    /// Pre-flight sampling said the post is already beyond repair.
    PreflightImpossible,
    /// A library entry's post has since been taken down.
    Gone,
    /// Anything on THIS machine: disk full, permissions, a write error,
    /// no usable servers, a bad config, an unpack that fell over. Says
    /// nothing about the post.
    Local,
}

impl FailKind {
    /// Is the post itself unavailable? Only these are worth telling an
    /// indexer about - the report marks a release dead for everyone else
    /// using it, and under `regrab` it spends a re-download too.
    pub(crate) fn post_unavailable(self) -> bool {
        !matches!(self, FailKind::Local | FailKind::Transport)
    }

    /// Might simply waiting fix it? Propagation fills missing articles in
    /// all the time, and a repair can succeed once the last volumes land.
    /// A local fault will not fix itself, and retrying it immediately
    /// just runs the same job into the same full disk.
    pub(crate) fn transient(self) -> bool {
        matches!(
            self,
            FailKind::MissingArticles | FailKind::Unrepairable | FailKind::Transport
        )
    }
}

/// Did this failure message come from a full disk? One matcher for the
/// NZBGet SPACE verdict and the retry guidance, because each platform
/// spells it differently: Unix ENOSPC says "No space left on device",
/// Windows error 112 says "There is not enough space on the disk" - and
/// the Windows form was invisible to a check that only knew the Unix
/// words, so a tester's disk-full unpack reported as a generic unpack
/// failure. Takes the message in any case; lowercases internally.
///
/// The numeric forms are there because the OS spells the words in the
/// system language, but always appends "(os error N)" - and they are
/// gated to the platform whose number that is, because the daemon
/// classifies failures it produced itself: 112 is ERROR_DISK_FULL on
/// Windows but EHOSTDOWN on Unix, and an unguarded match would have
/// called a dead-host transport failure a full disk.
pub(crate) fn disk_full_failure(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("no space left")
        || m.contains("not enough space")
        || m.contains("disk full")
        // The pipeline's own mid-download verdict (see drain_network in
        // get/workers.rs): classified at the write by error KIND, so the
        // quoted OS text may be in any language or carry an odd code.
        || m.contains("out of disk space")
        // With the closing paren, so "os error 28" cannot match
        // "os error 280" - std's io::Error always prints "(os error N)".
        || (cfg!(windows) && m.contains("os error 112)"))
        || (cfg!(unix) && m.contains("os error 28)"))
}

/// Did the DOWNLOAD itself halt on storage exhaustion (the fast-halt
/// verdict from get/workers.rs), as opposed to a disk that filled at
/// the unpack? Keyed on the message OPENING like every `fail_kind`
/// clause - appended detail never moves it. The two want different
/// guidance (the unpack case re-runs only the unpack; this one resumes
/// the fetch from the journal) and different daemon handling: with the
/// min-free guard armed, this job goes back to the queue and the guard
/// holds it until space frees, exactly like the pick-time hold.
pub(crate) fn disk_full_mid_download(msg: &str) -> bool {
    msg.starts_with("out of disk space")
}

/// The classifier as a wire token, for history_json. The dashboard
/// composes a per-kind "what to do next" line in the user's language -
/// which needs the KIND, not the raw English diagnostic it was derived
/// from. Tokens, not sentences, same contract as `ArchiveShape`.
pub(crate) fn fail_kind_token(k: FailKind) -> &'static str {
    match k {
        FailKind::MissingArticles => "missing",
        FailKind::Transport => "transport",
        FailKind::Unrepairable => "unrepairable",
        FailKind::PreflightImpossible => "preflight",
        FailKind::Gone => "gone",
        FailKind::Local => "local",
    }
}

/// [`fail_kind_token`] read back, for the persisted job record.
///
/// TODO 307 item 1's job-level carry needs a wire spelling for
/// [`Job::fail_code`](crate::serve::job::Job), and this reuses the one
/// `history_json` has already published for years rather than minting a
/// second vocabulary for the same six values - two spellings of one enum
/// is a table that goes stale the first time a kind is added.
///
/// `None` for anything this build does not recognise, which is the same
/// answer an ABSENT key gets and is deliberately not an error: a token
/// written by a NEWER build naming a kind that did not exist here is
/// exactly the case where falling back to the sentence is the honest
/// answer, and `job_wire`'s schema rule says an additive key must never
/// refuse a record. Round-tripped against `fail_kind_token` by test, so
/// the pair cannot drift.
pub(crate) fn kind_from_token(tok: &str) -> Option<FailKind> {
    match tok {
        "missing" => Some(FailKind::MissingArticles),
        "transport" => Some(FailKind::Transport),
        "unrepairable" => Some(FailKind::Unrepairable),
        "preflight" => Some(FailKind::PreflightImpossible),
        "gone" => Some(FailKind::Gone),
        "local" => Some(FailKind::Local),
        _ => None,
    }
}

/// Tokens for the auto-retry's own reason - what the cooldown is WAITING
/// for, which is also what decided its length (see `SHORT_RETRY_SECS`).
pub(crate) const RETRY_WHY_TRANSPORT: &str = "transport";
pub(crate) const RETRY_WHY_PROPAGATION: &str = "propagation";

/// A sub-cause INSIDE the failure message, as a token, for the one action
/// the drawer offers beside the reason.
///
/// `fail_kind` answers "whose fault, and is it worth retrying"; this
/// answers "which button". Two failures can share a kind and need
/// opposite next moves: `MissingArticles` because a `retention_days`
/// setting excluded the segments is a settings row away from fixed, while
/// `MissingArticles` on a post carrying no PAR2 at all is only ever
/// answered by another release. Derived from the message like `fail_kind`
/// (and for the same reason - the sentence is what the pipeline hands
/// up), keyed on clauses `incomplete_reason` writes verbatim.
///
/// Empty means "no specific remedy": the kind's own action stands.
pub(crate) fn fail_hint(msg: &str) -> &'static str {
    if msg.starts_with("no usable servers") {
        // Nothing was even attempted: every configured server is out of
        // the pool. The message names them; the button opens the card.
        "servers"
    } else if msg.contains("configured retention") {
        "retention"
    } else if msg.contains("no PAR2 recovery data") {
        "nopar2"
    } else if msg.starts_with("the articles did not decode") {
        // The server's own copies are damaged - nothing on this machine
        // is wrong. Both of the clauses below land in `Local` (they are
        // neither missing articles nor a repair verdict), whose default
        // move is "show the folder"; the folder answers neither of them.
        "corrupt"
    } else if msg.starts_with("post size header disagrees") {
        // The poster's headers promise bytes that were never posted, so
        // asking again returns the same short post. Another release is
        // the only answer, exactly as for a takedown.
        "shortpost"
    } else if msg.contains("well past the minutes-to-hours") {
        // Last of the arms on purpose: this one is about the post's AGE,
        // not its shape, so anything more specific above (no parity at
        // all, a retention setting, a decode fault) is the better answer
        // and keeps it. It exists so the two surfaces that promise
        // "posts often finish propagating within the hour" can stop
        // saying that about a post days old - `incomplete_reason` writes
        // the clause, this names it, and the drawer picks the copy.
        "stale"
    } else {
        ""
    }
}

/// The ONE thing worth offering a failed job, as a token.
///
/// Generalizes the disk-full drawer row, which is the only failure the
/// dashboard ever gave a next move: everything else got the same generic
/// Retry, including the two kinds the classifier itself says a retry
/// cannot fix. Decided here rather than in the page because it is the
/// same classification `fail_kind` and `fail_hint` already do - and
/// because a rule ("a takedown is answered by another release, never by
/// asking again") deserves a test, which a template literal does not get.
///
/// Tokens: `password` (unlock), `space` (the live free-space block),
/// `servers`/`retention` (a settings row), `search` (find another
/// release), `path` (show the folder), `retry` (ask again).
pub(crate) fn fail_action(
    kind: FailKind,
    hint: &str,
    msg: &str,
    password_required: bool,
) -> &'static str {
    // Both of these outrank the kind: a locked archive and a full disk
    // are `Local`, and "show the folder" answers neither of them.
    // Password first is deliberate and pinned by
    // `each_failure_gets_the_action_that_can_help` - the unlock is the
    // one of the two that can be completed from the page. What must not
    // happen is a job being FLAGGED locked because it failed on a full
    // disk, and that is gated where the flag is raised (see the
    // `locked_probe` in `finalize_completed`), not here.
    if password_required {
        return "password";
    }
    if disk_full_failure(msg) {
        return "space";
    }
    // A sub-cause the message named beats the kind's default - see
    // `fail_hint` for why two MissingArticles can want opposite moves.
    match hint {
        "servers" => return "servers",
        "retention" => return "retention",
        "nopar2" | "shortpost" => return "search",
        // Damaged copies on the server: a re-fetch (and, with more than
        // one provider, a different one) is the whole remedy.
        "corrupt" => return "retry",
        _ => {}
    }
    match kind {
        // The post is the problem and asking again cannot change it.
        FailKind::Gone | FailKind::PreflightImpossible | FailKind::Unrepairable => "search",
        // Something on this machine: the folder is where the evidence is.
        FailKind::Local => "path",
        // Waiting, or the link settling, genuinely fixes these.
        FailKind::MissingArticles | FailKind::Transport => "retry",
    }
}

/// What one of the pool's typed failure codes means to the two policies
/// [`FailKind`] serves.
///
/// TODO 307 item 1's typed half. The mapping lives HERE and not in
/// `nzbkit` on purpose, and `nzbkit::fail`'s own header states the rule
/// from the other side: the pool records what it observed - a session
/// died, a read deadline expired, the fleet wound down - and knows
/// nothing about indexers, retry budgets or the button a page draws.
/// This function is the one place those observations become policy, so
/// the incident history that justifies the policy stays beside the
/// policy.
///
/// Every code maps to [`FailKind::Transport`] today, and that is a
/// finding rather than a placeholder: `FetchOutcome::Failed` is the
/// pool giving up on an article without a body, and NOT ONE of its four
/// causes is evidence about the post. Two of them
/// ([`FailCode::FleetExhausted`], [`FailCode::WorkerPanic`]) are not
/// even failures of the link - they are this process winding down or
/// falling over with the article still queued, and the 31 Jul 2026
/// stall is what happens when such a loss is read as the post's fault:
/// 94 files were reported short to the user AND to the indexer when
/// almost none of those articles had been asked for. `Transport` is the
/// kind that says "ours, not the post's", which is exactly right for
/// all four.
///
/// A code that ever maps somewhere else will be one the pool learns to
/// state about the POST rather than about itself, and it will arrive
/// with its own evidence. Written as an exhaustive match so adding one
/// is a decision made here rather than a default taken silently.
pub(crate) fn kind_of_code(code: FailCode) -> FailKind {
    match code {
        FailCode::Transport
        | FailCode::ReadStall
        | FailCode::FleetExhausted
        | FailCode::WorkerPanic => FailKind::Transport,
    }
}

/// [`fail_kind`], with the pool's typed code consulted FIRST where a
/// caller has one.
///
/// The point of the pairing, and the reason the string classifier is
/// still under it. A typed code is the truth recorded where it
/// happened; the sentence is the truth re-derived from prose several
/// files away, and a rewording in any of them moves the answer. So when
/// there is a code, it decides, and the sentence is not consulted at
/// all.
///
/// WHAT STILL ARRIVES WITH `None`: everything that is not one article's
/// fetch. This is the POOL's code and it is consumed at the pool
/// boundary (see `get::workers`). A JOB's terminal failure travels its
/// own way and carries [`FailKind`] itself - see [`job_kind`] and the
/// judgement written out there about why the pool's code could never
/// have served for it.
pub(crate) fn fail_kind_of(code: Option<FailCode>, msg: &str) -> FailKind {
    match code {
        Some(c) => kind_of_code(c),
        None => fail_kind(msg),
    }
}

/// [`fail_kind`], with the JOB's own stored code consulted FIRST.
///
/// TODO 307 item 1's second half, and the whole of what it buys: a
/// terminal failure used to reach the daemon as an `anyhow` message and
/// nothing else, so every job-terminal caller - the auto-retry gate, the
/// dead-post report, the hunt gates, the drawer's button, the *arr
/// status - rebuilt its answer by `starts_with` over a sentence
/// assembled several files away. A rewording anywhere in that chain
/// moved all of them at once with nothing going red. Now the producer
/// STATES the classification at the moment it decides it, and the
/// sentence is not consulted where it did.
///
/// **THE DESIGN JUDGEMENT, stated rather than smuggled in.** The pool's
/// [`FailCode`] could not serve here and never will: `nzbkit::fail`'s
/// own header forbids that type growing into an application
/// classification, and [`kind_of_code`] records the measurement behind
/// it - all four of its variants map to [`FailKind::Transport`], because
/// `FetchOutcome::Failed` is one article's fetch ending without a body
/// and NOT ONE of its causes is evidence about the post. A job's
/// terminal classification needs the four post-evidence kinds
/// ([`FailKind::MissingArticles`], [`FailKind::Unrepairable`],
/// [`FailKind::PreflightImpossible`], [`FailKind::Gone`]), and that
/// evidence exists only in `nzbfast` - the segment census in
/// `diag::incomplete_verdict`, the repair ladder's arithmetic, the
/// pre-flight sample, `health`'s give-up quorum. So the job's code is
/// `FailKind` itself: the value the string classifier exists to
/// reconstruct, recorded where it was decided instead of re-derived from
/// the prose it produced. It is deliberately NOT a new enum beside
/// `FailKind` - a second vocabulary for one classification is a table
/// that goes stale the first time a kind is added, and this one is
/// already published as a wire token by `history_json`.
///
/// **`None` is not a legacy arm and the string path is not dead code.**
/// It is the answer for every record persisted before the field existed,
/// for every failure whose producer has nothing better to say than the
/// error it caught (`e.to_string()` off an arbitrary `io::Error` is
/// `Local` by fallback and correctly so), and for the two surfaces that
/// hold a message without a job (`hunt::age_gate_open`,
/// `tasks::watch_fail_kind`). `failkind::tests::producers` stays the
/// load-bearing half of the test module for exactly that reason, and it
/// now also asserts, on every row, that the declared code and the
/// sentence agree - so the two cannot part company in silence.
pub(crate) fn job_kind(code: Option<FailKind>, msg: &str) -> FailKind {
    code.unwrap_or_else(|| fail_kind(msg))
}

/// A terminal job failure whose PRODUCER classified it, carried up the
/// `anyhow` chain so the daemon does not have to re-read the sentence.
///
/// The download pipeline hands its verdict to `serve::postproc` as an
/// `anyhow::Error` and the daemon stamps `e.to_string()` onto the job.
/// That is the string boundary this whole module sits on, and it is the
/// one place a code has to survive if `Job::fail_code` is to be anything
/// but empty. So the error IS the pairing: [`Display`](std::fmt::Display)
/// is the message verbatim - byte for byte what `anyhow::bail!(msg)`
/// produced before, including the `with_build` tag - and the kind rides
/// beside it where only [`code_of_error`] looks.
///
/// Nothing about the log, the SAB-compat surface or `fail_message`
/// changes. That is the point: this is additive at the string boundary
/// exactly as `fail_code` is additive on the wire.
#[derive(Debug)]
pub(crate) struct Classified {
    kind: FailKind,
    message: String,
}

impl Classified {
    pub(crate) fn new(kind: FailKind, message: String) -> Self {
        Classified { kind, message }
    }
}

impl std::fmt::Display for Classified {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Classified {}

/// The kind a terminal error's producer declared, if it declared one.
///
/// Walks the whole `anyhow` chain rather than testing the head, because
/// a `.context(..)` anywhere between the producer and the daemon
/// replaces the Display without replacing the evidence - and that is the
/// case where the code is worth MORE than the sentence, not less, since
/// the sentence the classifier would have read is by then the context's.
pub(crate) fn code_of_error(e: &anyhow::Error) -> Option<FailKind> {
    e.chain()
        .find_map(|c| c.downcast_ref::<Classified>())
        .map(|c| c.kind)
}

pub(crate) fn fail_kind(msg: &str) -> FailKind {
    if msg.starts_with("download incomplete") {
        FailKind::MissingArticles
    } else if msg.starts_with("download failed on connection errors") {
        FailKind::Transport
    } else if msg.contains("repair could not complete") {
        FailKind::Unrepairable
    } else if msg.starts_with("pre-flight: articles missing beyond repair") {
        FailKind::PreflightImpossible
    } else if msg == "content no longer retrievable" || msg.starts_with("post is gone") {
        // A download that proved every article absent on every backbone
        // that answered. Deliberately NOT MissingArticles: that is
        // transient, and an automatic retry against a post nothing
        // carries only spends the same minutes proving it again.
        FailKind::Gone
    } else {
        FailKind::Local
    }
}

/// The clause `diag::incomplete_reason` leads with when the RECOVERY set
/// is what failed and the payload is all but whole (TODO 282 item 17),
/// and the two clauses it appends when the repair ladder could not get
/// the volumes or the post never carried enough of them.
///
/// These are the evidence [`another_copy_can_help`] reads out of a
/// `MissingArticles` message. Kept as constants beside the predicate
/// that uses them, the same way `fail_hint`'s clauses are: this module
/// takes a `&str` and nothing else, so a message the producer rewrites
/// must be caught by a round-trip TEST rather than by the type system -
/// `diag::main_tests::the_recovery_evidence_reads_back` and
/// `get::tail::a_shortfall_past_the_declared_recovery_reads_back` are
/// those tests, and they are the reason a wording change here goes red
/// where it is made instead of quietly emptying the predicate.
const RECOVERY_CASUALTY_CLAUSE: &str = "the recovery data is what failed, not the payload";
const RECOVERY_UNOBTAINABLE_CLAUSE: &str =
    "recovery volumes this repair needed could not be fetched";
// The span is deliberately the part BEFORE the figure and before the
// optional "(recovery set <id>)" tag, so both spellings the producer can
// emit carry it contiguously - see `repair::RepairShortfall::clause`.
const RECOVERY_SHORTFALL_CLAUSE: &str =
    "recovery block(s) needed but the recovery set that covers this damage carries only";

/// Does this failure message carry positive evidence that the RECOVERY
/// half of the post is what ended the job?
///
/// Three spellings, one verdict, and each is a different producer:
///
/// * the casualty headline, when the payload arrived all but whole and
///   the parity is what would not serve (TODO 282 item 17);
/// * the unobtainable clause, which is the same repair-ladder verdict
///   riding as an appended clause when the headline stood down because
///   the payload lost more than its admitted twentieth;
/// * the shortfall clause, which is the arithmetic - the post declares
///   fewer recovery blocks than the damage needs, so no provider and no
///   amount of asking again could ever have repaired it.
fn recovery_is_what_failed(msg: &str) -> bool {
    msg.contains(RECOVERY_CASUALTY_CLAUSE)
        || msg.contains(RECOVERY_UNOBTAINABLE_CLAUSE)
        || msg.contains(RECOVERY_SHORTFALL_CLAUSE)
}

/// Can ANOTHER COPY OF THIS RELEASE help - a spare that was held, or one
/// a search could still find?
///
/// TODO 305. This is deliberately NOT [`fail_action`], and the two
/// questions being different is the whole of why it exists:
/// `fail_action` answers **what should this person press**, and
/// this answers **can a different post of the same release finish what
/// this one could not**. They agree on most failures and part company on
/// exactly one family, which is the one TODO 282 was founded on.
///
/// THE MEASUREMENT. Round B (26 Aug 2026,
/// `research/RECOVERY-LADDER-YIELD-2026-08-26.md`) scored twelve
/// failures and found seven where another release is the only remedy the
/// product has and the drawer said "retry". They are one shape: a
/// payload that arrived all but whole over a recovery set that no server
/// would serve. `incomplete_reason` opens that message "download
/// incomplete" - which it MUST, because `fail_kind` keys on the opening
/// and TODO 283 item 13 records that the age gate depends on it - so the
/// kind is `MissingArticles` and the action is `retry`. TODO 284 built
/// its whole parked surface FOR this shape (its item 2 names it) and
/// then gated that surface on a predicate calling the death retryable.
///
/// WHY `fail_action` WAS NOT SIMPLY WIDENED, which TODO 305 rules on
/// directly. That token is not ours alone: the dashboard draws its
/// dimmed Retry and its `find another` button from it, and
/// `history_json` derives SAB's `retry` BOOLEAN from `== "retry"` - so
/// moving this family to `search` would tell every *arr, nzb360 and
/// LunaSea client that a row a journal-resume retry can still shorten
/// may not be asked for again. The remedy question is answerable on its
/// own evidence, so it gets its own predicate rather than a loosened
/// one.
///
/// WHAT IT IS NOT: an age. `parked_replaceable`'s own header states that
/// every clause it holds is a mechanism, and freshness is already held
/// by two mechanisms that are better placed for it - the parked offer is
/// withheld while an automatic retry is still armed, and the clicked
/// hunt applies TODO 282 section C's own age gate (`age_gate_open`) at
/// the moment it would spend bytes. A fresh post is therefore not
/// offered a replacement until it has actually retried and failed again.
///
/// THE COST OF THAT, STATED RATHER THAN LEFT TO BE FOUND: between the
/// spent retry and the message growing its age clause, a recovery-set
/// failure under a day old draws the offer while `age_gate_open` would
/// refuse the search behind it - the reader gets "the post is under 2
/// days old ... waiting is more likely to help" instead of a list. That
/// is not new and is not this predicate's to fix: a fresh
/// `Unrepairable` or `PreflightImpossible` row has drawn the offer over
/// the same refusal since TODO 284 shipped, neither kind being
/// age-gated, and the switch to a HELD spare works at any age on all of
/// them. Moving it would mean giving `parked_replaceable` an age, which
/// its own header rules out clause by clause.
///
/// SHAPE 6, THE `corrupt` HINT, WHICH TODO 305 ASKS TO BE SETTLED HERE
/// RATHER THAN LEFT: it stays OUT, and not on a judgement about
/// providers. "the articles did not decode" classifies [`FailKind::Local`],
/// and `hunt::hunt_gates` refuses any failure whose kind is not
/// `post_unavailable()` with `NoHunt::LocalFault` - "the failure was on
/// this machine, not in the post". Admitting it here would draw a button
/// the very next door refuses, which is the one thing TODO 282's *arr
/// arm refuses to ship. If a re-fetch against a damaged copy should
/// become a replaceable shape, the gate to move is that one, and the
/// question is whether a decode fault is really Local at fleet 1 - a
/// different change, with a different blast radius, on a different
/// classifier.
pub(crate) fn another_copy_can_help(
    kind: FailKind,
    hint: &str,
    msg: &str,
    password_required: bool,
) -> bool {
    // The same two overrides `fail_action` puts ahead of the kind, for
    // the same reasons: a locked archive is a password away from
    // finishing and a full disk is this machine's, and neither is
    // answered by a second copy of the release.
    if password_required || disk_full_failure(msg) {
        return false;
    }
    match hint {
        // The user's own configuration decided these. A second copy is
        // excluded by the same setting and fails identically.
        "servers" | "retention" => return false,
        // No parity at all, or bytes the poster never posted: another
        // release is the only answer either can have, which is what
        // `fail_action` already says about both.
        "nopar2" | "shortpost" => return true,
        // See the header - Local, and the hunt refuses it one door later.
        "corrupt" => return false,
        _ => {}
    }
    match kind {
        FailKind::Gone | FailKind::PreflightImpossible | FailKind::Unrepairable => true,
        FailKind::Local | FailKind::Transport => false,
        // The one arm that is not `fail_action` written twice, and the
        // whole point of the function. A plain missing-articles failure
        // is genuinely retryable - propagation fills gaps in all the
        // time - so this asks for POSITIVE evidence in the message that
        // the recovery half is what died, and admits nothing without it.
        FailKind::MissingArticles => recovery_is_what_failed(msg),
    }
}

#[cfg(test)]
#[path = "failkind/tests.rs"]
mod tests;
