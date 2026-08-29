//! What happens AFTER a download job fails: the post-job duties that
//! fire once, and the auto-retry policy that decides whether waiting
//! can help.
//!
//! The classifier these are built on (`FailKind` / `fail_kind`, the
//! hint, the action, the disk-full predicates) moved to
//! `crate::failkind` in TODO 276 item 3 - it takes a `&str` and owes
//! nothing to the daemon, and leaving it here made `crate::diag` depend
//! on `serve`. Everything below takes a `&Job`, which is why it stayed.
//! They are still only correct together - the cooldown and the dead-post
//! report had already drifted apart once - and the glob below is what
//! keeps them reading as one unit (TODO 106 code motion out of job.rs,
//! behaviour unchanged).

use super::*;
use crate::failkind::*;

/// What a finished job still owes the outside world. `None` means
/// nothing at all; `Some(failing)` says whether a failure report is due
/// on top of the script and the notifications.
///
/// A tombstoned job was DELETED by the user while it ran. The delete
/// aborts the pipeline, which surfaces as an `Err` and files the job
/// Failed, so without this every cancellation ran the pp-script, sent a
/// "Failed" notification, and - worst - reported a perfectly healthy post
/// to the indexer as dead and (under `regrab`) started an unattended
/// multi-GB re-download of the very title the user had just cancelled.
/// A tombstoned job is dropped rather than filed; it owes nobody
/// anything. The success race is covered too: if the fetch happened to
/// return `Ok` just before the abort landed, the job is still deleted.
pub(in crate::serve) fn post_job_duties(
    state: JobState,
    tombstone: bool,
    failure_mode: &str,
) -> Option<bool> {
    if tombstone {
        return None;
    }
    Some(failure_mode != "off" && state == JobState::Failed)
}

/// Could waiting plausibly have changed the answer? The age half of
/// `auto_retry_eligible`, which `transient()` alone cannot see.
///
/// `FailKind::MissingArticles` is transient at ANY age, and it is
/// transient for one reason: a release grabbed minutes after its pre
/// 430s on every server until the backbones fill in, which is
/// indistinguishable from a dead post except by the calendar. So the
/// retry ran against posts a week old too, spent a second full download
/// (~150 s and 1.9 GB on the 15 Aug case) proving the same 1965 segments
/// absent, and labelled the wait "propagation" for a post whose
/// propagation finished six days earlier.
///
/// [`crate::diag::GONE_MIN_AGE_DAYS`] is where this project already
/// draws that line, and this is the third caller to use it rather than a
/// fourth opinion about how long propagation takes.
///
/// Deliberately narrow in both directions:
///
/// * only the missing-articles class is gated. `Transport` is a fault on
///   THIS machine's link and says nothing whatever about the post, so it
///   retries at any age; `Unrepairable` is a repair verdict, whose retry
///   re-fetches gaps and can pull more recovery volumes.
/// * an unknown age retries, and so does a loss the census leaves
///   AMBIGUOUS - segments lost to transport errors or to a server that
///   never connected are ours to fix, not the post's, and a
///   journal-resume retry heals them. The cost of a wrong suppression is
///   a final failure; a wrong retry costs one duplicate download.
///
/// Suppressing here and not at the label in `daemon_park` is the point:
/// relabelling the cooldown would leave the second download running.
/// Note the reach - `post_job_plan` shares this predicate, so a
/// suppressed retry ALSO makes the failure final, which is what sends
/// the report, the FailureLink re-grab and the M14f duplicate promotion.
/// That is correct for a post this old: nothing is coming, and a held
/// alternative is the only thing that can still deliver the release.
///
/// Takes the KIND as a value rather than re-deriving it (TODO 307 item
/// 1): the caller has already asked the job for its classification, and
/// asking twice is how one predicate ends up answering about a code and
/// the other about the sentence.
fn retry_may_still_help(kind: FailKind, msg: &str) -> bool {
    if kind != FailKind::MissingArticles {
        return true;
    }
    !crate::diag::missing_articles_proven_stale(msg)
}

/// Will `park` arm an M32 automatic retry for this job? `secs` is the
/// configured cooldown (0 = the feature is off).
///
/// A free function so both callers - `park`, which arms it, and
/// `post_job_plan`, which has to know the answer BEFORE park runs -
/// share one predicate, and so it can be tested without a whole Daemon.
pub(in crate::serve) fn auto_retry_eligible(j: &Job, secs: u64) -> bool {
    secs > 0
        && j.state == JobState::Failed
        && !j.tombstone
        // A watchdog demotion goes back to the queue instead of history;
        // park returns before the retry block for it.
        && !j.demote
        && j.fail_kind().transient()
        && retry_may_still_help(j.fail_kind(), &j.fail_message)
        // ONE automatic retry. The retry itself bumps `retries` and
        // clears the stamp, so a second failure lands here ineligible -
        // and that is the failure that reports, re-grabs and promotes.
        && j.retries == 0
        && !j.library
        && !j.password_required
        && j.auto_retry_at.is_none()
}

/// What `run_post_job_hooks_gen` owes: `None` for nothing, `Some(failing)`
/// where `failing` also means "and this failure is final".
///
/// The failure report, the re-grab it can pull in, and the promotion of a
/// held M14f duplicate all treat a failure as the end of the story. Fired
/// on a failure the daemon has already decided to retry itself, they put
/// three grabs of one title on the user's block account for one transient
/// gap - and tell the indexer a live release is dead over a gap that
/// propagation is expected to fill.
///
/// Answered here, synchronously, rather than by reading `auto_retry_at`
/// from inside the spawned hooks: `park` arms that stamp AFTER the hooks
/// are spawned, so the field-read version is a race that merely looks
/// safe while pp-scripts and notifications stay slow.
pub(in crate::serve) fn post_job_plan(
    j: &Job,
    failure_mode: &str,
    auto_retry_secs: u64,
) -> Option<bool> {
    let failing = post_job_duties(j.state, j.tombstone, failure_mode)?;
    Some(failing && !auto_retry_eligible(j, auto_retry_secs))
}

/// Carry stored notification tokens onto an incoming list.
///
/// `get_config` never hands a token back - it is the Plex token /
/// Jellyfin API key / Kodi `user:password` - and the dashboard rebuilds
/// the whole list from the DOM and replaces it wholesale. So a blank
/// token means KEEP, and without this the first Apply after a page load
/// would wipe every credential the user had stored.
///
/// Matched on (kind, url, name), never on position: rows get reordered
/// and deleted between the load and the save, and an index match would
/// hand one target's credential to another. Failing that, on (kind,
/// name) alone when exactly one UNCLAIMED stored target answers to it -
/// correcting a typo'd host or port is the commonest edit there is, and
/// it must not silently throw the token away. Genuine ambiguity carries
/// nothing forward: being asked for the token again is better than
/// sending one server's credential to a different one.
///
/// "Unclaimed" is what stops the fallback stealing: a stored target that
/// some incoming row already matches exactly is that row's, so a second
/// row sharing only its name is a DIFFERENT server and must not inherit
/// its credential. Without that filter, adding a second same-kind target
/// under an existing target's name copied the first one's token onto it.
pub(in crate::serve) fn merge_notify_tokens(
    list: &mut [crate::notify::Target],
    old: &[crate::notify::Target],
) {
    // Computed up front, over the whole incoming list, so the answer does
    // not depend on the order the rows happen to arrive in.
    let claimed: Vec<bool> = old
        .iter()
        .map(|p| {
            list.iter()
                .any(|t| t.kind == p.kind && t.url == p.url && t.name == p.name)
        })
        .collect();
    for t in list
        .iter_mut()
        .filter(|t| t.token.is_empty() || t.secret.is_empty())
    {
        let exact = old
            .iter()
            .find(|p| p.kind == t.kind && p.url == t.url && p.name == t.name);
        let prev = exact.or_else(|| {
            let mut by_name = old
                .iter()
                .enumerate()
                .filter(|(i, p)| !claimed[*i] && p.kind == t.kind && p.name == t.name)
                .map(|(_, p)| p);
            by_name.next().filter(|_| by_name.next().is_none())
        });
        if let Some(prev) = prev {
            // §129 4a: the webhook signing secret is a credential with
            // the token's exact lifecycle - blank on save means KEEP.
            if t.token.is_empty() {
                t.token = prev.token.clone();
            }
            if t.secret.is_empty() {
                t.secret = prev.secret.clone();
            }
        }
    }
}
