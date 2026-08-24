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

/// Why a job failed, as far as the two policies that care are concerned:
/// the auto-retry cooldown (`park`) and the dead-post report
/// (`report_failure`). One classifier so they cannot drift apart - they
/// already had, and a disk-full run was both auto-retried onto the same
/// full disk AND reported to the indexer as a dead post.
///
/// Derived from `fail_message` rather than stored on the job: the
/// terminal failure arrives here as an `anyhow` message from the download
/// pipeline, so a field would be this same match written one layer
/// earlier plus a second thing to keep in step with the sentence.
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
