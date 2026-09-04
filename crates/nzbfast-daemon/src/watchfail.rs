//! The six states a dropped watch-folder file ends up in when it does
//! NOT become a job: the message strings, the classifier that reads them
//! back, the "is the release actually in hand" predicate, and the opaque
//! row handle the dashboard names a listed file by.
//!
//! These were in `tasks::watchfolder` beside the lane that WRITES them,
//! and the SAB facade plus `api::queue` both read all four - which made
//! two API-layer modules depend on the background-task lane for a string
//! table. Nothing here touches a `Daemon`, a request or the filesystem;
//! the lane still owns the scan, the enqueue and the quarantine move.
//!
//! Verbatim from `watchfolder.rs`, one nesting level removed: the
//! constants were an inner `mod watchfail` inside that file and are this
//! module itself now, so every `TRUNCATED` in the tree reads
//! exactly as it did.

/// The reasons a watch-folder file ends up listed rather than ingested.
///
/// Written as constants, and read back by [`watch_fail_kind`], because
/// four of the six are SUCCESSES: the release is queued (or was
/// downloaded weeks ago) and only the file on disk is unresolved. One
/// sentence for all six told a user their download "couldn't be read"
/// when it had in fact already finished, and offered a Delete that is
/// harmless for some of them and destroys the only copy for others.
/// Keeping the strings and the classifier in one place is what stops the
/// two drifting: an edit to a message that forgets the mapping would
/// silently demote that state back to the generic sentence.
/// No closing `</nzb>`, and the file has stopped growing. NOT
/// ingested - the only state where the user must act on the file.
pub const TRUNCATED: &str = "truncated: no closing </nzb>";
/// The identical NZB is already sitting in the queue.
pub const ALREADY_QUEUED: &str = "already queued";
/// ...and this one already finished downloading.
pub const ALREADY_DONE: &str = "already downloaded";
/// Queued, but the queue record could not be persisted, so the file
/// is deliberately KEPT as the recovery copy.
pub const UNSAVED: &str = "queued, but the queue record could not be saved";
/// Queued and durable, but the source file could not be removed.
/// Prefix: the OS error is appended.
pub const KEPT: &str = "queued, but the file could not be removed";

/// Opaque, stable identity for one tracked watch-folder rejection
/// (Codex sweep 2, 3 Aug L1).
///
/// The queue payload names these rows by basename, which is not an
/// identity: change the watch directory and a rejected `same.nzb` can
/// be tracked in both the old and the new one, leaving the user two
/// identical-looking rows and the delete handler picking whichever
/// HashMap iteration reached first. A digest of the FULL path names the
/// row exactly. Truncated to 16 hex chars - this is a handle for a set
/// with a handful of members, not a credential - and deliberately not
/// the path itself, which the browser has no business holding.
pub fn watch_fail_id(path: &std::path::Path) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(path.as_os_str().as_encoded_bytes());
    hex::encode(h.finalize())[..16].to_string()
}

/// Which of the six [`watchfail`] states a listed file is in, as a token
/// the dashboard switches on. `"rejected"` is the sixth: an `enqueue`
/// error, i.e. the only case besides `truncated` where the file really
/// could not be used.
///
/// F6, CHECKED AND DELIBERATELY NOT GIVEN A SEVENTH STATE (the
/// zero-declared-bytes handoff, claim `nzb-zero-bytes-downstream`). A
/// `NzbError::TooLarge` refusal - a STRUCTURAL ceiling in
/// `nzbkit::nzb::limits`, not a syntax problem - lands here as
/// `"rejected"`, so the strip prints this module's generic "couldn't be
/// read" with the daemon's own reason beside it, and the file did in
/// fact read perfectly. That is the very class this module's own header
/// argues about, one state further along, so a seventh kind with its
/// own sentence is the obvious answer and it was priced and declined:
/// every one of those ceilings is sized so nothing real reaches it
/// (`MAX_SEGMENTS` is 1,000,000 against a largest real fixture of
/// 11,060, and each constant states its own margin), so the population
/// that ever sees the sentence is somebody handed a hostile or corrupt
/// manifest - for whom "couldn't be read", with the dimension named
/// immediately after it, is both true enough and the more useful
/// framing. A new UI string is also 27 catalogue translations under
/// CI's i18n gate, spent on a sentence essentially nobody reads. Revisit
/// only if a ceiling is ever LOWERED to a figure real posts approach.
pub fn watch_fail_kind(msg: &str) -> &'static str {
    if msg == TRUNCATED {
        "truncated"
    } else if msg == ALREADY_QUEUED {
        "queued"
    } else if msg == ALREADY_DONE {
        "done"
    } else if msg == UNSAVED {
        "unsaved"
    } else if msg.starts_with(KEPT) {
        "kept"
    } else {
        "rejected"
    }
}

/// Is this listed file's release actually in hand? True for the four
/// states where the queue (or history) owns it and only the file on disk
/// is unfinished business - which is exactly the set where deleting the
/// file is safe and "couldn't be read" is a lie.
pub fn watch_fail_ingested(kind: &str) -> bool {
    matches!(kind, "queued" | "done" | "unsaved" | "kept")
}
