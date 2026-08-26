//! Why the pool gave up on an article, as a value rather than a
//! sentence.
//!
//! [`FetchOutcome::Failed`](crate::pool::FetchOutcome::Failed) has
//! carried a `String` since it was written, and the application then
//! rebuilds policy from that text: `nzbfast`'s `failkind` module decides
//! retry, dead-post reporting and the button a failed job is offered by
//! `starts_with`/`contains` over English sentences several files
//! format independently. The 26 Aug 2026 code-quality review (TODO 307
//! item 1) named that as the tree's highest-value typed boundary, and
//! the reason is what a rewording costs: `Transport` says nothing about
//! the post and must never be reported to an indexer, `MissingArticles`
//! is exactly what an indexer wants to hear about, and one edited
//! opening moves a healthy release from the first to the second with
//! nothing anywhere going red.
//!
//! THIS TYPE IS NOT THE APPLICATION'S CLASSIFICATION and must not grow
//! into one. Every variant below is a fact this crate observes at the
//! moment it happens - a session died, a read deadline expired, the
//! fleet wound down - and nothing here knows what an indexer is, what a
//! retry costs, or which button a page should draw. `nzbfast` maps
//! these to its own `FailKind`, in `nzbfast`, which is where the policy
//! and its incident history live. A variant whose name is a policy
//! word is a variant in the wrong crate.
//!
//! THE STRING STAYS, and that is deliberate rather than transitional.
//! It is the log surface, the SAB-compat surface and the `anyhow`
//! surface, it quotes the OS's own wording in the OS's own language,
//! and it carries detail no enum should try to hold. What changes is
//! that a reader which only needs to know WHICH KIND of failure it was
//! no longer has to parse it.

/// Why one article's fetch ended without a body.
///
/// Deliberately small, and every variant is a distinct thing the pool
/// DID rather than a shade of wording. Two of them are not transport
/// failures at all in the sense a provider would recognise - the fleet
/// running out of workers and a worker panicking are OUR faults, and a
/// consumer that treats them as evidence about the post is making the
/// mistake `nzbfast`'s `FailKind::Transport` exists to prevent, one
/// layer down.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailCode {
    /// A session carrying this article died or refused to carry it: the
    /// peer closed or reset, a write or flush failed, and the article's
    /// retry budget was spent. The link, not the post.
    Transport,
    /// OUR read deadline ended the session while the article was in
    /// flight. Its own variant rather than a shade of [`Self::Transport`]
    /// because the peer never said anything: this is a budget WE chose,
    /// and a consumer sizing that budget wants to count it separately
    /// from a peer that actually hung up.
    ReadStall,
    /// No connection worker was left to fetch it. The run wound down -
    /// every server out of sessions, out of connect attempts, or gone -
    /// with work still queued, so this article was never asked for by
    /// anyone. Says nothing whatsoever about the post; see
    /// `PoolStats::left_mid_run` for what that silence used to cost.
    FleetExhausted,
    /// A pool worker panicked before this article was fetched. Kept
    /// apart from [`Self::FleetExhausted`] because it is a BUG here and
    /// wants to read as one wherever it surfaces, not as a fleet that
    /// simply ran out.
    WorkerPanic,
}

impl FailCode {
    /// The sentence the pool states this code in, when a caller needs
    /// one - a log line, or the `error` field beside the code.
    ///
    /// Derived FROM the code rather than chosen beside it, which is the
    /// whole point of the pairing: the seal path used to pick its
    /// reason string in an `if` and hand it down, so a code added later
    /// would have been free to disagree with the sentence sent with it.
    /// A caller with more to say (the OS's own words for a reset, a
    /// failing write) still sends its own string; this is the floor,
    /// not a ceiling.
    pub fn reason(self) -> &'static str {
        match self {
            FailCode::Transport => "the connection carrying this article failed",
            FailCode::ReadStall => "read stall",
            FailCode::FleetExhausted => "no connection worker left to fetch this article",
            FailCode::WorkerPanic => "a pool worker panicked before this article was fetched",
        }
    }
}
