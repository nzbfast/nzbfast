//! The caller-visible per-server run statistics: what the pool REPORTS
//! about each server once a run ends. Split out of pool.rs whole
//! (TODO 106 size gate, 28 Aug 2026 - the file was one line under its
//! ceiling); the `pub use` in pool.rs keeps every `pool::PoolStats` /
//! `pool::SessionEnds` spelling unchanged.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Read every server's run statistics off the shared state, once the
/// run is sealed. `counters` is the per-server `(bytes, connects,
/// reconnects)` triple the fleet was dealt.
///
/// THE ONE PLACE the report is assembled. Both run entry points end
/// here - the async `fetch_all_multi` and the blocking sharded path -
/// and until 28 Aug 2026 each spelled the whole struct out for itself,
/// twenty-six identical lines apiece. That is the shape
/// `Shared::missing_cause` already carries a warning about in its own
/// doc: a rule written out twice is one that holds in one of them. It
/// was not hypothetical here either - `fence_retired` was added to
/// both by hand, and a field added to one alone reads as absent on
/// whichever path the run happened to take, with nothing to say which
/// path that was.
pub(super) fn run_stats(
    shared: &super::Shared,
    counters: &[(Arc<AtomicU64>, Arc<AtomicU64>, Arc<AtomicU64>)],
) -> Vec<PoolStats> {
    counters
        .iter()
        .enumerate()
        .map(|(si, (b, c, r))| PoolStats {
            bytes: b.load(Ordering::Relaxed),
            connects: c.load(Ordering::Relaxed),
            reconnects: r.load(Ordering::Relaxed),
            ever_connected: shared.connected[si].load(Ordering::Relaxed),
            left_mid_run: shared.left_mid_run[si].load(Ordering::Relaxed),
            ends: shared.session_ends(si),
            miss_proven: shared
                .miss_answers
                .get(si)
                .map_or(0, |m| m[0].load(Ordering::Relaxed)),
            miss_bare: shared
                .miss_answers
                .get(si)
                .map_or(0, |m| m[1].load(Ordering::Relaxed)),
            fence_retired: shared
                .fence_off
                .get(si)
                .is_some_and(|f| f.load(Ordering::Relaxed)),
            blocked_ms: shared
                .blocked_ms
                .get(si)
                .map_or(0, |c| c.load(Ordering::Relaxed)),
        })
        .collect()
}

#[derive(Debug, Default)]
pub struct PoolStats {
    pub bytes: u64,
    pub connects: u64,
    pub reconnects: u64,
    /// Did ANY worker ever hold a usable connection to this server (fresh
    /// dial or warm-pool hand-me-down)? False means the server sat out
    /// the entire run - unreachable, or it refused the login - so every
    /// "unanimous 430" verdict was reached without its vote. The failure
    /// summary names such servers; without that, one dead backup silently
    /// turns a single 430 into "missing segments".
    pub ever_connected: bool,
    /// Did this server connect, serve, and then LEAVE while the run still
    /// had work outstanding - a permanent refusal, a prepaid block or
    /// quota spent, the cumulative outage budget blown, the
    /// connect-attempt cap? All four end with the server's last worker
    /// returning, and until this bit existed all four were SILENT.
    ///
    /// `ever_connected` cannot see it: that stays TRUE for a server that
    /// worked for ten minutes and then walked out. So nothing said the
    /// quorum had shrunk while `live_mask` (able to serve NOW) stopped counting
    /// the leaver, and the survivors' 430s on the segments it alone
    /// carried read as unanimous. What that cost - a healthy post
    /// reported gone, the one automatic retry suppressed, and with it the
    /// indexer dead-report, FailureLink re-grab and duplicate promotion -
    /// is written up at `LossCauses::left_servers` (audit 20 Aug, A3).
    ///
    /// Never true for a server that never connected at all: that is
    /// `ever_connected == false`, its own clause and its own sentence.
    pub left_mid_run: bool,
    /// WHY this server's sessions ended, counted where it happens.
    ///
    /// `reconnects` alone says a session died and was redialled; it does
    /// not say who hung up. That gap cost a whole investigation on 6 Aug
    /// 2026: a provider churning 148 sessions in one 190 GB job had six
    /// hypotheses eliminated one at a time (fan-out, hedge, slope
    /// recycle, connection count, provider idle timeout, the pre-byte
    /// budget) purely by exclusion, because "session lost, redialled"
    /// reads identically for a peer FIN, a peer reset, our own read
    /// timeout, our own quit and a protocol desync. See
    /// research/PROVIDER-CHURN-2026-08-06.md.
    pub ends: SessionEnds,
    /// Authoritative 430/423 wire answers whose attribution was PROVEN:
    /// the refusal line echoed a message-id, or the dispatch was fenced
    /// (§129 3g), so it cannot have been filed on the wrong article. A
    /// proven refusal really is this server saying "that article is not
    /// here".
    pub miss_proven: u64,
    /// Authoritative 430/423 wire answers that were BARE - no echoed
    /// id, filed against the pipeline front by position alone. On a
    /// desynced socket a bare refusal can belong to the article behind,
    /// which is why `soft_430` demands a confirming repeat before one
    /// reaches the mask. This count beside `ends.protocol` is what lets
    /// a leg log say whether a run's Missing verdicts rest on evidence
    /// that could have been misfiled (the 28 Aug 2026 g25L question -
    /// see the field on `Shared`).
    pub miss_bare: u64,
    /// §129 3g: this server's alignment fence was RETIRED mid-run -
    /// it never answered a DATE, so two duds turned the check off and
    /// every later refusal from it is BARE and positional again.
    ///
    /// It matters for reading the two counts above, and nothing else
    /// reported it: `Shared::note_fence_dud`'s only outward sign is a
    /// `fence-off` event on the dashboard's in-memory ring, which a CLI
    /// leg has no reader for at all - so on a bench log the retirement
    /// was invisible and its absence proved nothing. With the fence UP,
    /// a non-echoing provider spends ONE bare answer per absent article
    /// and every one after that arrives fenced and proven, so the bare
    /// column stays near the article count while the proven column runs
    /// ahead of it; with the fence RETIRED, `miss_proven` stops growing
    /// at all and every terminal verdict rests on BARE refusals, which
    /// is the misattribution the fence exists to remove. The same
    /// reading means opposite things either side of that: a bare-heavy
    /// skew is one thing when the fence is up and another when it is
    /// gone.
    ///
    /// HOW MANY PROVEN ANSWERS PER ARTICLE IS NOT A CONSTANT, since
    /// TODO 315. Before that it was one, and this doc said so; the late
    /// re-ask (`PoolConfig::recheck_430`) adds one more against the
    /// LAST live backbone, so a single-provider run now spends two per
    /// absent article and a leg measured before the re-ask landed spent
    /// one. Read the two columns against each other, never against a
    /// remembered absolute.
    pub fence_retired: bool,
    /// Milliseconds this server's workers spent parked because the
    /// fetch->decode channel was FULL - i.e. waiting on decode, verify
    /// and the disk rather than on the network. The daemon has always
    /// had this (`ServerLive::blocked_ms`); the CLI did not, so a
    /// bench leg could not tell a NETWORK dip from a WRITE-SIDE dip -
    /// which is exactly the question a periodic throughput sawtooth
    /// asks (6 Aug: full rate for 8-9 s, then a drop to 8-21% of peak,
    /// repeating, costing ~12-15% of an 87 GB job).
    pub blocked_ms: u64,
}

/// Per-server tally of how sessions ENDED, by cause.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SessionEnds {
    /// The peer closed or reset the connection, or the socket failed
    /// under us: an I/O-flavoured `NntpError`. THIS is "the provider
    /// hung up on us".
    pub peer: u64,
    /// A well-formed but unusable answer - the response did not parse,
    /// or the echoed message-id did not match what we asked for.
    pub protocol: u64,
    /// Our own pre-first-byte budget expired: the server had not
    /// started answering in time. Distinguished from `stall` because
    /// giving up pre-byte is our budget CHOICE, not evidence the peer
    /// is dead (TODO 121.1).
    pub prebyte: u64,
    /// Our own mid-flow deadline expired: bytes were moving and
    /// stopped. That is a genuine wedge.
    pub stall: u64,
    /// We hung up deliberately - shed for promoted work, over the live
    /// connection target, or a pipeline deeper than a mid-window cap.
    pub ours: u64,
}
