//! The classification matrix, pinned against the sentences the pipeline
//! actually emits.
//!
//! Everything in `failkind` takes a `&str` and answers a small value, and
//! the module header explains at length why that is the right shape:
//! the terminal failure reaches the daemon as an `anyhow` message and a
//! field would be this same match written one layer earlier. What that
//! design cannot do is notice a REWORDING. `fail_kind` decides whether a
//! release is reported to an indexer as a dead post, and it decides that
//! by `starts_with` over an English sentence some other file formats -
//! so a producer that reworded its opening would move a healthy release
//! from `Transport` (never reported) to `MissingArticles` (reported, and
//! auto-retried) with nothing anywhere going red.
//!
//! The classifications WERE partly pinned before this module existed, by
//! roughly eight test files each pinning the one arm it cared about
//! (`diag::main_tests` on the openings it produces, `serve::job_tests` on
//! the disk-full spellings, `serve::tests_grabs` on the pre-flight verdict,
//! `serve::hunt_tests` on the parked offer). Nothing pinned the MATRIX,
//! and nothing tied the matrix to the producers - which is the half that
//! catches a rewording, because a literal in a test file is a copy of the
//! sentence and moves only when somebody edits the test.
//!
//! So this module has two halves and needs both:
//!
//! * **`producers`** builds each message by CALLING the code that emits
//!   it - `diag::incomplete_reason` with real `LossCauses`, and
//!   `repair::RepairShortfall::clause` - and asserts the classification
//!   off the result. A rewording upstream reddens here.
//! * **`matrix`** drives every arm of every predicate as a table,
//!   including the arms no producer reaches today (`Gone`'s exact-match
//!   spelling, the hint precedence order, the two disk-full platform
//!   forms). A producer that stops emitting a shape leaves that shape's
//!   rule pinned rather than silently untested.
//!
//! Read the two together: neither is redundant, and the failure they
//! report is different. A red in `producers` means a sentence moved; a
//! red in `matrix` means a RULE moved.
//!
//! WHAT THIS MODULE DELIBERATELY DOES NOT DO is assert that any
//! particular classification is CORRECT. It is a characterization
//! module: it records what the tree decides today so a change to the
//! decision is visible in the diff that makes it. Every judgement about
//! whether a kind is the right kind lives in the doc comments on the
//! items themselves, and those carry the incident history that justifies
//! them.

use super::{
    FailKind, another_copy_can_help, disk_full_failure, disk_full_mid_download, fail_action,
    fail_hint, fail_kind, fail_kind_of, fail_kind_token, kind_of_code,
};
use crate::diag::{LossCauses, incomplete_reason, with_build};
use nzbkit::fail::FailCode;

/// A `LossCauses` with nothing wrong, to spread over.
///
/// Its own copy rather than `diag::main_tests`'s: that one is private to
/// that module, and more to the point a shared fixture is a shared
/// oracle - a lane tuning main_tests' baseline would silently move what
/// this module characterizes. `par2_slots: 1` matches it, because a post
/// with no parity at all earns the `nopar2` hint and that is a separate
/// row below.
fn quiet() -> LossCauses<'static> {
    LossCauses {
        missing_430: 0,
        takedown_430: 0,
        retention_excluded: 0,
        transport_failed: 0,
        missing_430_recovery: 0,
        takedown_430_recovery: 0,
        retention_excluded_recovery: 0,
        transport_failed_recovery: 0,
        recovery_segments: 0,
        recovery_unobtainable: false,
        transport_sample: None,
        decode_sample: None,
        recovery_errs: 0,
        dead_servers: &[],
        left_servers: &[],
        par2_slots: 1,
        stalled: false,
        missing_segments: 0,
        total_segments: 0,
        bytes_arrived: 0,
        backbones: &[],
        post_age_days: 0,
    }
}

/// Every answer the module gives about one message, as one value.
///
/// Taken as a whole rather than asserted one predicate at a time because
/// the predicates are not independent: `fail_action` reads `fail_kind`
/// AND `fail_hint` AND `disk_full_failure`, so a row that pins only the
/// kind can go green while the button the user is offered has moved.
#[derive(Debug, PartialEq, Eq)]
struct Verdict {
    kind: FailKind,
    token: &'static str,
    hint: &'static str,
    action: &'static str,
    /// `fail_action` again with `password_required` set, which is the one
    /// input that is not the message and outranks everything in it.
    action_locked: &'static str,
    disk_full: bool,
    mid_download: bool,
    post_unavailable: bool,
    transient: bool,
    another_copy: bool,
}

fn verdict(msg: &str) -> Verdict {
    let kind = fail_kind(msg);
    let hint = fail_hint(msg);
    Verdict {
        kind,
        token: fail_kind_token(kind),
        hint,
        action: fail_action(kind, hint, msg, false),
        action_locked: fail_action(kind, hint, msg, true),
        disk_full: disk_full_failure(msg),
        mid_download: disk_full_mid_download(msg),
        post_unavailable: kind.post_unavailable(),
        transient: kind.transient(),
        another_copy: another_copy_can_help(kind, hint, msg, false),
    }
}

/// Assert the whole verdict, and assert it AGAIN through `with_build`.
///
/// `diag::with_build` appends " [nzbfast X.Y.Z]" to every message the
/// download pipeline bails with, and its own header states the contract
/// this checks: appended, never prefixed, because the daemon classifies
/// on the OPENING. Every producer row therefore has to survive it -
/// which is also what stops a rule being written `ends_with`.
#[track_caller]
fn assert_verdict(msg: &str, want: Verdict) {
    let got = verdict(msg);
    assert_eq!(got, want, "classification of: {msg}");
    let tagged = with_build(msg.to_string());
    let got_tagged = verdict(&tagged);
    assert_eq!(
        got_tagged, want,
        "the build tag moved a classification, which with_build's contract forbids: {tagged}"
    );
}

/// Rows whose message is built by the code that emits it in production.
///
/// A rewording in `diag::incomplete_reason`, `get::plan`, `get::tail` or
/// `repair::RepairShortfall` reddens here. That is the whole point of
/// the module: a literal copied into a test file cannot notice a
/// producer being rewritten, and the string boundary this classifier
/// sits on has no other guard.
mod producers {
    use super::*;

    /// The plain missing-segments opening: the commonest failure there
    /// is, and the one whose kind decides whether a healthy release is
    /// reported dead.
    #[test]
    fn a_plain_short_download_is_missing_articles_and_offers_retry() {
        let msg = incomplete_reason(
            3,
            0,
            &LossCauses {
                missing_430: 12,
                missing_segments: 12,
                total_segments: 4506,
                bytes_arrived: 1_879_000_000,
                par2_slots: 4,
                ..quiet()
            },
        );
        assert!(msg.starts_with("download incomplete"), "{msg}");
        assert_verdict(
            &msg,
            Verdict {
                kind: FailKind::MissingArticles,
                token: "missing",
                hint: "",
                action: "retry",
                action_locked: "password",
                disk_full: false,
                mid_download: false,
                post_unavailable: true,
                transient: true,
                // No positive evidence the RECOVERY half is what died,
                // so a second copy is not offered - see
                // `another_copy_can_help`'s MissingArticles arm.
                another_copy: false,
            },
        );
    }

    /// The stall: OUR failure, and the reason the `Transport` kind
    /// exists at all. It must never be `post_unavailable`, because that
    /// is what files a takedown report against a healthy post.
    #[test]
    fn a_stalled_pool_is_transport_and_is_never_reportable() {
        let msg = incomplete_reason(
            94,
            0,
            &LossCauses {
                stalled: true,
                missing_430: 0,
                par2_slots: 4,
                ..quiet()
            },
        );
        assert!(
            msg.starts_with("download failed on connection errors"),
            "{msg}"
        );
        assert_verdict(
            &msg,
            Verdict {
                kind: FailKind::Transport,
                token: "transport",
                hint: "",
                action: "retry",
                action_locked: "password",
                disk_full: false,
                mid_download: false,
                post_unavailable: false,
                transient: true,
                another_copy: false,
            },
        );
    }

    /// The all-transport opening, which is the same kind reached by a
    /// different arm of the same function: every loss was a transport
    /// failure and no server ever said 430.
    #[test]
    fn an_all_transport_loss_is_transport_too() {
        let msg = incomplete_reason(
            2,
            0,
            &LossCauses {
                transport_failed: 40,
                missing_segments: 40,
                total_segments: 900,
                par2_slots: 2,
                ..quiet()
            },
        );
        assert!(
            msg.starts_with("download failed on connection errors"),
            "{msg}"
        );
        assert_eq!(fail_kind(&msg), FailKind::Transport, "{msg}");
        assert!(!fail_kind(&msg).post_unavailable(), "{msg}");
        assert_eq!(
            fail_action(FailKind::Transport, fail_hint(&msg), &msg, false),
            "retry"
        );
    }

    /// The post proved absent on every backbone that answered. `Gone` is
    /// deliberately NOT transient: an automatic retry against a post
    /// nothing carries only spends the same minutes proving it again.
    #[test]
    fn a_wholly_absent_post_is_gone_and_is_not_retried() {
        let msg = incomplete_reason(
            5,
            0,
            &LossCauses {
                missing_430: 240,
                missing_segments: 240,
                total_segments: 240,
                bytes_arrived: 0,
                par2_slots: 0,
                post_age_days: 9,
                ..quiet()
            },
        );
        assert!(msg.starts_with("post is gone"), "{msg}");
        // No hint, even though this post carries no parity at all: the
        // `no PAR2 recovery data` clause stands down on the `post_gone`
        // opening, which has already said every article of every file
        // was absent. The kind's own default is `search` regardless.
        assert_verdict(
            &msg,
            Verdict {
                kind: FailKind::Gone,
                token: "gone",
                hint: "",
                action: "search",
                action_locked: "password",
                disk_full: false,
                mid_download: false,
                post_unavailable: true,
                transient: false,
                another_copy: true,
            },
        );
    }

    /// The poster's headers promise bytes that were never posted.
    /// `Local`, because nothing about the post is missing - and the
    /// `shortpost` hint is what turns the folder button into a search.
    #[test]
    fn a_short_post_is_local_but_the_hint_offers_a_search() {
        let msg = incomplete_reason(
            1,
            0,
            &LossCauses {
                missing_segments: 0,
                total_segments: 240,
                bytes_arrived: 900_000_000,
                par2_slots: 2,
                ..quiet()
            },
        );
        assert!(msg.starts_with("post size header disagrees"), "{msg}");
        assert_verdict(
            &msg,
            Verdict {
                kind: FailKind::Local,
                token: "local",
                hint: "shortpost",
                action: "search",
                action_locked: "password",
                disk_full: false,
                mid_download: false,
                post_unavailable: false,
                transient: false,
                another_copy: true,
            },
        );
    }

    /// TODO 282 item 17: the recovery set is the casualty and the
    /// payload is all but whole. It keeps the missing-articles OPENING
    /// on purpose (the age gate depends on it), so the kind and the
    /// action are unchanged - and `another_copy_can_help` is the one
    /// predicate that reads the clause and answers differently.
    #[test]
    fn a_recovery_casualty_keeps_its_kind_and_still_offers_another_copy() {
        let msg = incomplete_reason(
            1,
            0,
            &LossCauses {
                missing_430: 1,
                missing_segments: 4,
                total_segments: 4000,
                bytes_arrived: 13_000_000_000,
                recovery_segments: 60,
                missing_430_recovery: 60,
                par2_slots: 4,
                ..quiet()
            },
        );
        assert!(
            msg.contains("the recovery data is what failed, not the payload"),
            "{msg}"
        );
        assert_verdict(
            &msg,
            Verdict {
                kind: FailKind::MissingArticles,
                token: "missing",
                hint: "",
                action: "retry",
                action_locked: "password",
                disk_full: false,
                mid_download: false,
                post_unavailable: true,
                transient: true,
                another_copy: true,
            },
        );
    }

    /// The other two spellings of the same evidence, each written by a
    /// different producer. `another_copy_can_help` reads all three and
    /// must keep answering true for each on its own.
    #[test]
    fn both_appended_recovery_clauses_also_open_the_parked_offer() {
        let unobtainable = incomplete_reason(
            2,
            0,
            &LossCauses {
                missing_430: 30,
                missing_segments: 300,
                total_segments: 4000,
                bytes_arrived: 12_000_000_000,
                recovery_unobtainable: true,
                par2_slots: 4,
                ..quiet()
            },
        );
        assert!(
            unobtainable.contains("recovery volumes this repair needed could not be fetched"),
            "{unobtainable}"
        );
        assert_eq!(fail_kind(&unobtainable), FailKind::MissingArticles);
        assert!(
            another_copy_can_help(
                fail_kind(&unobtainable),
                fail_hint(&unobtainable),
                &unobtainable,
                false
            ),
            "{unobtainable}"
        );

        // The arithmetic clause `get::tail` appends off
        // `RepairShortfall::Blocks`, on a missing-articles opening.
        let shortfall = crate::repair::RepairShortfall::Blocks { needed: 9, have: 8 }.clause();
        let with_clause = format!(
            "{}; {shortfall}",
            incomplete_reason(
                1,
                0,
                &LossCauses {
                    missing_430: 9,
                    missing_segments: 9,
                    total_segments: 4000,
                    bytes_arrived: 12_000_000_000,
                    par2_slots: 4,
                    ..quiet()
                },
            )
        );
        assert!(
            with_clause.contains("recovery block(s) needed but the NZB only carries"),
            "{with_clause}"
        );
        assert_eq!(fail_kind(&with_clause), FailKind::MissingArticles);
        assert!(
            another_copy_can_help(
                fail_kind(&with_clause),
                fail_hint(&with_clause),
                &with_clause,
                false
            ),
            "{with_clause}"
        );
    }

    /// Damaged copies on the server, nothing missing. `Local` - nothing
    /// on this machine is wrong either, but the kind's own default
    /// action ("show the folder") answers neither, so the `corrupt`
    /// hint overrides it with a re-fetch.
    #[test]
    fn corrupt_articles_are_local_and_offer_retry_but_never_another_copy() {
        let msg = incomplete_reason(
            0,
            7,
            &LossCauses {
                // The producer's own verdict, not the sentence's
                // opening words: `workers.rs` records `corrupt` at the
                // site that saw the yEnc check fail. Before 26 Aug 2026
                // `diag` re-derived this from `starts_with("decode
                // error")`, so this construction is what changed here -
                // the whole pinned matrix below is unmoved.
                decode_sample: Some(crate::diag::DecodeSample::corrupt(
                    "decode error: pcrc32 mismatch".to_string(),
                )),
                ..quiet()
            },
        );
        assert!(msg.starts_with("the articles did not decode"), "{msg}");
        assert_verdict(
            &msg,
            Verdict {
                kind: FailKind::Local,
                token: "local",
                hint: "corrupt",
                action: "retry",
                action_locked: "password",
                disk_full: false,
                mid_download: false,
                post_unavailable: false,
                transient: false,
                // See the header on `another_copy_can_help`: the hunt
                // gate refuses a Local failure one door later, so
                // admitting it here would draw a button nothing honours.
                another_copy: false,
            },
        );
    }

    /// A write fault with nothing missing: this machine's problem, and
    /// the folder is where the evidence is.
    #[test]
    fn a_write_fault_is_local_and_points_at_the_folder() {
        let msg = incomplete_reason(
            0,
            2,
            &LossCauses {
                decode_sample: Some(crate::diag::DecodeSample::write(
                    "write error: Permission denied".to_string(),
                )),
                ..quiet()
            },
        );
        assert!(msg.starts_with("could not write the download"), "{msg}");
        assert_verdict(
            &msg,
            Verdict {
                kind: FailKind::Local,
                token: "local",
                hint: "",
                action: "path",
                action_locked: "password",
                disk_full: false,
                mid_download: false,
                post_unavailable: false,
                transient: false,
                another_copy: false,
            },
        );
    }

    /// The same write fault, on a FULL disk. `disk_full_failure` reads
    /// the quoted OS text and outranks the kind's own action - the
    /// folder does not answer a full volume, the free-space block does.
    #[test]
    fn a_write_fault_on_a_full_disk_offers_space_not_the_folder() {
        let msg = incomplete_reason(
            0,
            2,
            &LossCauses {
                decode_sample: Some(crate::diag::DecodeSample::write(
                    "write error: No space left on device (os error 28)".to_string(),
                )),
                ..quiet()
            },
        );
        assert_verdict(
            &msg,
            Verdict {
                kind: FailKind::Local,
                token: "local",
                hint: "",
                action: "space",
                action_locked: "password",
                disk_full: true,
                // The unpack/settle case, not the fetch halt - the
                // opening is what tells the two apart.
                mid_download: false,
                post_unavailable: false,
                transient: false,
                another_copy: false,
            },
        );
    }

    /// A `retention_days` setting excluded the segments: a settings row
    /// away from fixed, so neither a retry nor another copy - a second
    /// copy of the release is excluded by the same setting.
    #[test]
    fn a_retention_exclusion_hints_at_the_setting_and_refuses_another_copy() {
        let msg = incomplete_reason(
            2,
            0,
            &LossCauses {
                retention_excluded: 40,
                missing_segments: 40,
                total_segments: 900,
                par2_slots: 2,
                ..quiet()
            },
        );
        assert!(msg.contains("configured retention"), "{msg}");
        assert_verdict(
            &msg,
            Verdict {
                kind: FailKind::MissingArticles,
                token: "missing",
                hint: "retention",
                action: "retention",
                action_locked: "password",
                disk_full: false,
                mid_download: false,
                post_unavailable: true,
                transient: true,
                another_copy: false,
            },
        );
    }

    /// A post carrying no parity at all: nothing can rebuild a confirmed
    /// missing segment, so another release is the only answer either
    /// surface has.
    #[test]
    fn a_post_with_no_parity_offers_a_search_and_another_copy() {
        let msg = incomplete_reason(
            1,
            0,
            &LossCauses {
                missing_430: 3,
                missing_segments: 3,
                total_segments: 900,
                bytes_arrived: 400_000_000,
                par2_slots: 0,
                ..quiet()
            },
        );
        assert!(msg.contains("no PAR2 recovery data"), "{msg}");
        assert_verdict(
            &msg,
            Verdict {
                kind: FailKind::MissingArticles,
                token: "missing",
                hint: "nopar2",
                action: "search",
                action_locked: "password",
                disk_full: false,
                mid_download: false,
                post_unavailable: true,
                transient: true,
                another_copy: true,
            },
        );
    }

    /// The age clause, and its documented place LAST in the hint order:
    /// a post days old with a sharper fault named earlier keeps the
    /// sharper hint.
    #[test]
    fn an_aged_post_is_hinted_stale_only_when_nothing_sharper_applies() {
        let aged = incomplete_reason(
            1,
            0,
            &LossCauses {
                missing_430: 3,
                missing_segments: 3,
                total_segments: 900,
                bytes_arrived: 400_000_000,
                par2_slots: 4,
                post_age_days: 40,
                ..quiet()
            },
        );
        assert!(aged.contains("well past the minutes-to-hours"), "{aged}");
        assert_verdict(
            &aged,
            Verdict {
                kind: FailKind::MissingArticles,
                token: "missing",
                hint: "stale",
                action: "retry",
                action_locked: "password",
                disk_full: false,
                mid_download: false,
                post_unavailable: true,
                transient: true,
                another_copy: false,
            },
        );

        // Same age, but the post also carries no parity: `nopar2` is
        // the better answer and keeps the hint.
        let aged_no_parity = incomplete_reason(
            1,
            0,
            &LossCauses {
                missing_430: 3,
                missing_segments: 3,
                total_segments: 900,
                bytes_arrived: 400_000_000,
                par2_slots: 0,
                post_age_days: 40,
                ..quiet()
            },
        );
        assert!(
            aged_no_parity.contains("well past the minutes-to-hours"),
            "{aged_no_parity}"
        );
        assert_eq!(fail_hint(&aged_no_parity), "nopar2", "{aged_no_parity}");
    }

    /// `get::plan` bails before a single article is asked for. Both
    /// spellings open with the same four words, which is what the
    /// `servers` hint keys on.
    #[test]
    fn no_usable_servers_hints_at_the_server_card_in_both_spellings() {
        for msg in [
            "no usable servers: none are set up yet - add your provider in Server settings",
            "no usable servers: every one you have set up is out of the pool right now - \
             news.example (busy, refused the login, or out of block data)",
        ] {
            assert_verdict(
                msg,
                Verdict {
                    kind: FailKind::Local,
                    token: "local",
                    hint: "servers",
                    action: "servers",
                    action_locked: "password",
                    disk_full: false,
                    mid_download: false,
                    post_unavailable: false,
                    transient: false,
                    another_copy: false,
                },
            );
        }
    }

    /// `get::tail`'s two repair openings, and the shortfall clause each
    /// carries. Both classify `Unrepairable`: transient enough for the
    /// one automatic retry, and `search` rather than `retry`.
    #[test]
    fn both_repair_verdicts_are_unrepairable_and_offer_a_search() {
        let bare = "verification failed and PAR2 repair could not complete".to_string();
        let blocks = format!(
            "verification failed and PAR2 repair could not complete: {}",
            crate::repair::RepairShortfall::Blocks {
                needed: 20,
                have: 8
            }
            .clause()
        );
        for msg in [bare, blocks] {
            assert_verdict(
                &msg,
                Verdict {
                    kind: FailKind::Unrepairable,
                    token: "unrepairable",
                    hint: "",
                    action: "search",
                    action_locked: "password",
                    disk_full: false,
                    mid_download: false,
                    post_unavailable: true,
                    transient: true,
                    another_copy: true,
                },
            );
        }
    }

    /// `get::workers`'s mid-download halt. Distinct from the unpack
    /// disk-full case by its OPENING, which is what
    /// `disk_full_mid_download` keys on - the two want different daemon
    /// handling, so a message that merely mentions a full disk must not
    /// answer this predicate.
    #[test]
    fn the_mid_download_halt_is_the_only_message_that_answers_mid_download() {
        let msg = "out of disk space - the output volume filled during the download, \
                   so fetching was stopped early; what landed is journaled and kept \
                   (write error: No space left on device (os error 28))";
        assert_verdict(
            msg,
            Verdict {
                kind: FailKind::Local,
                token: "local",
                hint: "",
                action: "space",
                action_locked: "password",
                disk_full: true,
                mid_download: true,
                post_unavailable: false,
                transient: false,
                another_copy: false,
            },
        );
    }

    /// The pre-flight sample said the post is already beyond repair.
    /// Not transient - nothing about waiting changes arithmetic - and
    /// the answer is another release.
    #[test]
    fn the_preflight_verdict_is_never_retried_and_offers_a_search() {
        let msg = "pre-flight: articles missing beyond repair - 12 of 240 sampled \
                   segment(s) are absent on every server";
        assert_verdict(
            msg,
            Verdict {
                kind: FailKind::PreflightImpossible,
                token: "preflight",
                hint: "",
                action: "search",
                action_locked: "password",
                disk_full: false,
                mid_download: false,
                post_unavailable: true,
                transient: false,
                another_copy: true,
            },
        );
    }

    /// The library-side verdicts. `health`'s give-up sentence keeps the
    /// `post is gone` opening (its own test asserts that too, from the
    /// producer's end); `tasks`'s watchlist verdict is the ONE message
    /// `fail_kind` matches by equality rather than by prefix.
    #[test]
    fn the_library_verdicts_are_gone() {
        let health = "post is gone: all 8 sampled article(s) were reported missing by every one \
                      of the 3 server(s) that answered";
        assert_eq!(fail_kind(health), FailKind::Gone, "{health}");
        assert_eq!(fail_kind("content no longer retrievable"), FailKind::Gone);
        // Exact match, so anything appended falls through to Local. That
        // is the current rule, recorded rather than endorsed - the
        // producer writes the string as a whole literal and nothing
        // appends to it.
        assert_eq!(
            fail_kind("content no longer retrievable now"),
            FailKind::Local
        );
    }

    /// The messages the daemon writes for itself rather than the
    /// download pipeline. All `Local`: none of them says anything about
    /// the post, and the folder is where the evidence is.
    #[test]
    fn the_daemons_own_verdicts_are_all_local() {
        for msg in [
            "stopped by user",
            "paused (drained in-flight; queue kept for resume)",
            "deleted from the queue",
            "password required to unpack",
            "post-processing crashed (internal error) - retry the job to re-run it",
            "post-processing was interrupted by a restart; the download itself completed \
             and its files are under /tmp/out",
            "download complete, but 2 partial metadata file(s) could not be removed: a.nfo, \
             b.sfv - refusing to report success while a holed file that looks real remains \
             in the output directory (fix permissions and retry)",
        ] {
            assert_eq!(fail_kind(msg), FailKind::Local, "{msg}");
            assert!(!fail_kind(msg).post_unavailable(), "{msg}");
            assert!(!fail_kind(msg).transient(), "{msg}");
        }
    }
}

/// The rules themselves, driven arm by arm.
///
/// Where `producers` asks "does the sentence still classify the way it
/// did", this asks "does the rule still say what it said" - including
/// for shapes no producer emits today, and for the precedence between
/// clauses that a real message rarely exercises alone.
mod matrix {
    use super::*;

    /// Every `fail_kind` arm, and the ORDER they are tested in. The
    /// order is load-bearing: `download incomplete` is matched before
    /// `repair could not complete`, so the recovery-casualty message -
    /// which can carry both - stays `MissingArticles`.
    #[test]
    fn every_fail_kind_arm_including_its_precedence() {
        let rows: &[(&str, FailKind)] = &[
            ("download incomplete: 1 file(s)", FailKind::MissingArticles),
            (
                "download failed on connection errors: 1 file(s)",
                FailKind::Transport,
            ),
            (
                "verification failed and PAR2 repair could not complete",
                FailKind::Unrepairable,
            ),
            (
                "pre-flight: articles missing beyond repair (12 segments)",
                FailKind::PreflightImpossible,
            ),
            ("content no longer retrievable", FailKind::Gone),
            (
                "post is gone: not one of the 240 article(s)",
                FailKind::Gone,
            ),
            (
                "could not write the download: 2 decode/write",
                FailKind::Local,
            ),
            ("", FailKind::Local),
            // The `repair could not complete` arm is a `contains`, so it
            // reaches a message that merely mentions it - but only after
            // the two openings above it have been ruled out.
            (
                "post-processing failed: repair could not complete",
                FailKind::Unrepairable,
            ),
            // Precedence: opening wins over the contains.
            (
                "download incomplete: 1 file(s); repair could not complete",
                FailKind::MissingArticles,
            ),
            (
                "download failed on connection errors: 1 file(s); repair could not complete",
                FailKind::Transport,
            ),
        ];
        for (msg, want) in rows {
            assert_eq!(fail_kind(msg), *want, "{msg}");
        }
    }

    /// The two policy questions every kind answers, as a closed table.
    /// A new variant added without a decision here fails to compile,
    /// which is the point of writing it as an exhaustive match.
    #[test]
    fn every_kind_answers_both_policy_questions() {
        for kind in [
            FailKind::MissingArticles,
            FailKind::Transport,
            FailKind::Unrepairable,
            FailKind::PreflightImpossible,
            FailKind::Gone,
            FailKind::Local,
        ] {
            let (reportable, transient, token) = match kind {
                FailKind::MissingArticles => (true, true, "missing"),
                FailKind::Transport => (false, true, "transport"),
                FailKind::Unrepairable => (true, true, "unrepairable"),
                FailKind::PreflightImpossible => (true, false, "preflight"),
                FailKind::Gone => (true, false, "gone"),
                FailKind::Local => (false, false, "local"),
            };
            assert_eq!(kind.post_unavailable(), reportable, "{kind:?}");
            assert_eq!(kind.transient(), transient, "{kind:?}");
            assert_eq!(fail_kind_token(kind), token, "{kind:?}");
        }
    }

    /// Every `fail_hint` arm and the precedence between them, in the
    /// order the function tests. `stale` is last on purpose (its own
    /// comment says why), so every other clause beats it.
    #[test]
    fn every_fail_hint_arm_and_its_precedence() {
        let rows: &[(&str, &str)] = &[
            ("no usable servers: none are set up yet", "servers"),
            (
                "download incomplete: older than every configured retention",
                "retention",
            ),
            (
                "download incomplete: this post carries no PAR2 recovery data",
                "nopar2",
            ),
            (
                "the articles did not decode: 7 damaged article(s)",
                "corrupt",
            ),
            ("post size header disagrees with its parts", "shortpost"),
            (
                "download incomplete: well past the minutes-to-hours",
                "stale",
            ),
            ("download incomplete: 1 file(s) with missing segments", ""),
            ("", ""),
        ];
        for (msg, want) in rows {
            assert_eq!(fail_hint(msg), *want, "{msg}");
        }

        // Precedence, pair by pair, in the order the arms are written.
        // Each left-hand clause must beat each right-hand one.
        let sharper: &[(&str, &str)] = &[
            ("no usable servers: ", "configured retention"),
            ("no usable servers: ", "no PAR2 recovery data"),
            ("no usable servers: ", "well past the minutes-to-hours"),
            (
                "download incomplete: configured retention",
                "no PAR2 recovery data",
            ),
            (
                "download incomplete: configured retention",
                "well past the minutes-to-hours",
            ),
            (
                "download incomplete: no PAR2 recovery data",
                "well past the minutes-to-hours",
            ),
            (
                "the articles did not decode: ",
                "well past the minutes-to-hours",
            ),
            (
                "post size header disagrees: ",
                "well past the minutes-to-hours",
            ),
        ];
        for (lead, also) in sharper {
            let combined = format!("{lead}; {also}");
            assert_eq!(
                fail_hint(&combined),
                fail_hint(lead),
                "the sharper clause must keep the hint: {combined}"
            );
        }

        // `corrupt` and `shortpost` are OPENINGS: a message that merely
        // mentions either wording keeps whatever its own opening says.
        assert_eq!(
            fail_hint("download incomplete: the articles did not decode"),
            ""
        );
        assert_eq!(
            fail_hint("download incomplete: post size header disagrees"),
            ""
        );
    }

    /// `fail_action` in full: both overrides, every hint arm, and every
    /// kind's default. Written as a table so a moved arm shows as one
    /// changed row.
    #[test]
    fn every_fail_action_arm() {
        // password_required outranks everything, including a full disk -
        // the unlock is the one of the two that can be completed from
        // the page.
        assert_eq!(
            fail_action(FailKind::Local, "", "no space left on device", true),
            "password"
        );
        assert_eq!(
            fail_action(FailKind::Gone, "nopar2", "post is gone", true),
            "password"
        );
        // A full disk outranks the kind and every hint.
        for hint in [
            "",
            "servers",
            "retention",
            "nopar2",
            "shortpost",
            "corrupt",
            "stale",
        ] {
            assert_eq!(
                fail_action(FailKind::MissingArticles, hint, "disk full", false),
                "space",
                "hint {hint}"
            );
        }
        // The hint arms, over a kind whose own default is different.
        let hint_rows: &[(&str, &str)] = &[
            ("servers", "servers"),
            ("retention", "retention"),
            ("nopar2", "search"),
            ("shortpost", "search"),
            ("corrupt", "retry"),
            // Not a hint `fail_action` reads: the kind decides.
            ("stale", "retry"),
            ("", "retry"),
        ];
        for (hint, want) in hint_rows {
            assert_eq!(
                fail_action(
                    FailKind::MissingArticles,
                    hint,
                    "download incomplete",
                    false
                ),
                *want,
                "hint {hint}"
            );
        }
        // The kind defaults, with no hint and no override.
        let kind_rows: &[(FailKind, &str)] = &[
            (FailKind::Gone, "search"),
            (FailKind::PreflightImpossible, "search"),
            (FailKind::Unrepairable, "search"),
            (FailKind::Local, "path"),
            (FailKind::MissingArticles, "retry"),
            (FailKind::Transport, "retry"),
        ];
        for (kind, want) in kind_rows {
            assert_eq!(
                fail_action(*kind, "", "some failure", false),
                *want,
                "{kind:?}"
            );
        }
    }

    /// `another_copy_can_help` in full. It agrees with `fail_action`
    /// everywhere except the `MissingArticles` arm, which asks for
    /// positive evidence in the message instead of answering on the kind.
    #[test]
    fn every_another_copy_arm() {
        assert!(!another_copy_can_help(
            FailKind::Gone,
            "",
            "post is gone",
            true
        ));
        assert!(!another_copy_can_help(
            FailKind::Gone,
            "",
            "post is gone: no space left on device",
            false
        ));
        let hint_rows: &[(&str, bool)] = &[
            ("servers", false),
            ("retention", false),
            ("nopar2", true),
            ("shortpost", true),
            ("corrupt", false),
        ];
        for (hint, want) in hint_rows {
            assert_eq!(
                another_copy_can_help(FailKind::Local, hint, "whatever", false),
                *want,
                "hint {hint}"
            );
        }
        let kind_rows: &[(FailKind, bool)] = &[
            (FailKind::Gone, true),
            (FailKind::PreflightImpossible, true),
            (FailKind::Unrepairable, true),
            (FailKind::Local, false),
            (FailKind::Transport, false),
            // No evidence in the message: refused.
            (FailKind::MissingArticles, false),
        ];
        for (kind, want) in kind_rows {
            assert_eq!(
                another_copy_can_help(*kind, "", "download incomplete: 1 file(s)", false),
                *want,
                "{kind:?}"
            );
        }
        // The three recovery clauses, each on its own. All three are
        // written verbatim by a producer and read back here; the
        // producer-side round trip is in `producers` above.
        for clause in [
            "the recovery data is what failed, not the payload",
            "recovery volumes this repair needed could not be fetched",
            "recovery block(s) needed but the NZB only carries",
        ] {
            let msg = format!("download incomplete: 1 file(s); {clause} 8");
            assert!(
                another_copy_can_help(FailKind::MissingArticles, "", &msg, false),
                "{msg}"
            );
            // The evidence is only ever read on the MissingArticles arm:
            // every other kind answers on the kind alone.
            assert!(!another_copy_can_help(FailKind::Transport, "", &msg, false));
        }
    }

    /// `disk_full_failure`: every spelling, the case-insensitivity, and
    /// the platform gating. The numeric forms are guarded because 112 is
    /// ERROR_DISK_FULL on Windows and EHOSTDOWN on Unix - an unguarded
    /// match called a dead-host transport failure a full disk.
    #[test]
    fn every_disk_full_spelling_and_its_platform_gate() {
        for msg in [
            "write error: No space left on device",
            "WRITE ERROR: NO SPACE LEFT ON DEVICE",
            "There is not enough space on the disk",
            "the disk full condition stopped the unpack",
            "out of disk space - the output volume filled",
        ] {
            assert!(disk_full_failure(msg), "{msg}");
        }
        for msg in [
            "download incomplete: 1 file(s) with missing segments",
            "verification failed and PAR2 repair could not complete",
            "no usable servers: none are set up yet",
            // Without the closing paren: std always prints one, so this
            // is a different code and must not match.
            "write error: os error 280",
            "write error: os error 1122",
        ] {
            assert!(!disk_full_failure(msg), "{msg}");
        }
        // The numeric arms, each true only on the platform whose number
        // it is. Written this way rather than under #[cfg] so both arms
        // are stated in one place and the gating itself is the assertion.
        assert_eq!(
            disk_full_failure("write error: (os error 28)"),
            cfg!(unix),
            "os error 28 is ENOSPC on unix only"
        );
        assert_eq!(
            disk_full_failure("write error: (os error 112)"),
            cfg!(windows),
            "os error 112 is ERROR_DISK_FULL on windows and EHOSTDOWN on unix"
        );
    }

    /// `disk_full_mid_download` keys on the OPENING alone, which is what
    /// separates the fetch halt (resume from the journal, and the
    /// min-free guard holds the job) from a disk that filled at the
    /// unpack (re-run only the unpack).
    #[test]
    fn mid_download_keys_on_the_opening_only() {
        assert!(disk_full_mid_download(
            "out of disk space - the output volume filled during the download"
        ));
        // Appended detail never moves it.
        assert!(disk_full_mid_download(&with_build(
            "out of disk space - filled".to_string()
        )));
        for msg in [
            "unpack failed: out of disk space",
            "write error: No space left on device",
            "download incomplete: 1 file(s)",
        ] {
            assert!(!disk_full_mid_download(msg), "{msg}");
            // ... while the wider predicate still sees the first two.
        }
        assert!(disk_full_failure("unpack failed: out of disk space"));
    }
}

/// The typed half: TODO 307 item 1's `FailCode` arriving from the pool.
///
/// Where `producers` and `matrix` characterize the STRING classifier,
/// this pins the code path that is meant to make the string classifier
/// unnecessary wherever a caller has a code - and pins the one property
/// that makes the pairing safe, which is that the two never disagree.
mod typed {
    use super::*;

    /// Every code maps to `Transport`, and every one of them is asserted
    /// rather than inferred from the collapsed match arm. `FetchOutcome::Failed`
    /// is the pool giving up on an article without a body, and not one
    /// of its four causes is evidence about the POST - two of them are
    /// this process winding down or falling over with the article still
    /// queued. A code that ever leaves this column is a policy change
    /// and has to be made here, in the open.
    #[test]
    fn every_pool_code_is_ours_and_never_the_posts_fault() {
        for code in [
            FailCode::Transport,
            FailCode::ReadStall,
            FailCode::FleetExhausted,
            FailCode::WorkerPanic,
        ] {
            let kind = kind_of_code(code);
            assert_eq!(kind, FailKind::Transport, "{code:?}");
            assert!(
                !kind.post_unavailable(),
                "{code:?} must never be reportable to an indexer as a dead post"
            );
            assert!(kind.transient(), "{code:?} is worth one more attempt");
            assert_eq!(fail_kind_token(kind), "transport", "{code:?}");
        }
    }

    /// The code DECIDES and the sentence is not consulted at all - which
    /// is the whole point, and is only visible on a message whose own
    /// opening says something else. `post is gone` classifies `Gone` as
    /// a string, and a `FleetExhausted` code over it must still answer
    /// `Transport`: nobody asked for the article, so nothing about the
    /// post was established.
    #[test]
    fn a_code_outranks_whatever_the_sentence_says() {
        let lying = "post is gone: not one of the 240 article(s) is on any server";
        assert_eq!(fail_kind(lying), FailKind::Gone);
        assert_eq!(
            fail_kind_of(Some(FailCode::FleetExhausted), lying),
            FailKind::Transport
        );
        assert_eq!(
            fail_kind_of(
                Some(FailCode::WorkerPanic),
                "download incomplete: 1 file(s)"
            ),
            FailKind::Transport
        );
    }

    /// With no code, `fail_kind_of` IS `fail_kind` - which is the arm
    /// every job-terminal caller is on today, for the reason
    /// `fail_kind_of`'s header states. Driven over the whole producer
    /// vocabulary rather than one row, because this equivalence is what
    /// lets the string classifier stay under the typed one without
    /// anybody having to check it again.
    #[test]
    fn without_a_code_the_answer_is_exactly_the_string_classifiers() {
        for msg in [
            "download incomplete: 1 file(s) with missing segments",
            "download failed on connection errors: the connection pool stalled",
            "verification failed and PAR2 repair could not complete",
            "pre-flight: articles missing beyond repair (12 segments)",
            "content no longer retrievable",
            "post is gone: not one of the 240 article(s)",
            "no usable servers: none are set up yet",
            "out of disk space - the output volume filled during the download",
            "could not write the download: 2 decode/write error(s)",
            "",
        ] {
            assert_eq!(fail_kind_of(None, msg), fail_kind(msg), "{msg}");
        }
    }

    /// The pool derives its own sentence FROM the code, so a reader that
    /// has only the string still lands where the code says. That is what
    /// stops the pairing drifting: before item 1 the seal path picked a
    /// reason in an `if` and handed it down beside nothing, so a code
    /// added later would have been free to disagree with it.
    ///
    /// `FailCode::Transport`'s own sentence is the floor rather than the
    /// ceiling - a session death sends the OS's own words instead - so
    /// this asserts the property that holds for every code: the reason
    /// is non-empty, distinct, and classifies as the code does wherever
    /// the string classifier has an opinion at all.
    #[test]
    fn the_pools_own_reason_never_contradicts_its_code() {
        let codes = [
            FailCode::Transport,
            FailCode::ReadStall,
            FailCode::FleetExhausted,
            FailCode::WorkerPanic,
        ];
        let mut seen: Vec<&str> = Vec::new();
        for code in codes {
            let reason = code.reason();
            assert!(!reason.is_empty(), "{code:?}");
            assert!(
                !seen.contains(&reason),
                "two codes share a sentence: {reason}"
            );
            seen.push(reason);
            // None of the pool's own sentences may accidentally open a
            // clause the string classifier reads as the POST's fault.
            // They fall through to `Local` today, which is not the code's
            // answer - and that difference is exactly why the code is
            // consulted first rather than the sentence being tuned to
            // match it.
            assert_eq!(fail_kind_of(Some(code), reason), FailKind::Transport);
            assert!(
                !fail_kind(reason).post_unavailable(),
                "the pool's own wording must never read as a dead post: {reason}"
            );
        }
    }
}
