//! The queue payload's notice rings, and the one property they all
//! share: every mutation must move `queue_rev`.
//!
//! These strips ride the revisioned queue payload (§129 1b), and
//! `m_dashboard` answers `queue: null` while `client_q == qrev` - so an
//! idle page re-renders them from the payload it already holds, and a
//! mutation that does not move the revision is applied on the daemon
//! and NOWHERE else. Five separate rings have now been bitten by it
//! (the update banner, `set_limit`, `watch_failed_*`, `publish_hold`
//! and `delete_kept`), which is why they are pinned together here.
//!
//! A child of daemon_tests, moved out by the size gate (TODO 106). The
//! module is named for its file so size-gate.py's CFG_TEST_MOD resolver
//! still reads it as test code; `use super::*` brings the harness
//! (`with_daemon`) and everything it reaches.

// The daemon crate's root vocabulary, which `use super::*` reached while
// this file lived there: `super::` means `serve` here, and serve's globs
// carry the daemon UNITS but not that crate root's own imports.
use nzbfast_daemon::MutexExt;
use nzbfast_daemon::testutil::with_daemon;
use std::sync::atomic::Ordering;

/// The watch-failed strip rides the revisioned queue payload, so every
/// mutation of the map must move `queue_rev` - an idle dashboard skips
/// the payload while `client_q == qrev`, and an entry removed without a
/// bump renders forever: its delete button answers "no such rejected
/// file" for a row the daemon dropped long ago (reported 14 Aug 2026;
/// the third instance of the payload-rider trap after the update banner
/// and set_limit). No-op mutations must NOT bump, or every 5 s watch
/// pass would re-send the payload to every idle tab.
#[test]
fn watch_failed_mutations_move_the_queue_rev() {
    with_daemon("wfrev", |d| {
        let dir = std::env::temp_dir().join(format!("nzbfast-wfrev-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let present = dir.join("present.nzb");
        std::fs::write(&present, b"x").unwrap();
        let gone = dir.join("gone.nzb");
        let rev = || d.queue_rev.load(Ordering::Relaxed);
        let val = |s: &str| (1u64, 2u64, s.to_string(), String::new());

        let r0 = rev();
        assert!(d.watch_failed_insert(present.clone(), val("truncated")));
        assert_eq!(rev(), r0 + 1, "a fresh insert must bump");
        assert!(
            !d.watch_failed_insert(present.clone(), val("truncated")),
            "re-inserting the identical row is the every-pass no-op"
        );
        assert_eq!(rev(), r0 + 1, "the no-op re-insert must not bump");
        assert!(d.watch_failed_insert(present.clone(), val("kept")));
        assert_eq!(rev(), r0 + 2, "a changed value must bump");

        d.watch_failed_remove(&gone);
        assert_eq!(rev(), r0 + 2, "removing an absent row must not bump");
        d.watch_failed_remove(&present);
        assert_eq!(rev(), r0 + 3, "a real removal must bump");

        d.watch_failed_insert(present.clone(), val("truncated"));
        d.watch_failed_insert(gone.clone(), val("truncated"));
        let r1 = rev();
        d.watch_failed_prune_missing();
        assert_eq!(rev(), r1 + 1, "pruning a vanished file must bump");
        assert!(
            d.watch_failed.lock_ok().contains_key(&present),
            "pruning must keep entries whose file is still on disk"
        );
        d.watch_failed_prune_missing();
        assert_eq!(rev(), r1 + 1, "an empty prune must not bump");
        let _ = std::fs::remove_dir_all(&dir);
    });
}

/// The kept-files strip rides the revisioned queue payload too, so both
/// doors to the ring must move `queue_rev` - and `spend_kept_notice`,
/// which the dismiss button and the "download it again" button both go
/// through, was the one missing it. An idle dashboard is answered
/// `queue: null` while `client_q == qrev`, so it re-renders the strip
/// from the payload it already holds: the button cleared the entry on
/// the daemon and nowhere else, and the notice sat there until the page
/// was reloaded. Reported by a Windows tester on 16 Aug 2026; invisible
/// in development because `m_dashboard`'s `any_active` arm re-sends the
/// payload every second whenever anything is transferring, so only an
/// IDLE daemon shows it. Fifth instance of the payload-rider trap after
/// the update banner, `set_limit`, `watch_failed_*` and `publish_hold`.
///
/// The path is Windows-shaped, with a space in the folder name, because
/// the reported one was: the notice's identity is the path STRING, and
/// this pins that what `queue_json` serves is byte-identical to what
/// `spend_kept_notice` matches on. `Path::display()` does not rewrite
/// separators on any host, so the string travels intact from a Unix CI
/// box too.
#[test]
fn delete_kept_mutations_move_the_queue_rev() {
    with_daemon("dkrev", |d| {
        let win = r"C:\Users\GS\Downloads\nzbfast downloads\Some.Release-RAWR";
        let p = std::path::Path::new(win);
        let rev = || d.queue_rev.load(Ordering::Relaxed);
        let why = "the Trash would not take it";

        let r0 = rev();
        d.note_delete_kept("Some.Release-RAWR", p, why, None);
        assert_eq!(rev(), r0 + 1, "a fresh notice must bump");
        d.note_delete_kept("Some.Release-RAWR", p, why, None);
        assert_eq!(
            rev(),
            r0 + 1,
            "the same path twice is the dedupe no-op and must not bump"
        );

        // What the dashboard is actually handed, and therefore what its
        // dismiss button sends back.
        let served = crate::sabcompat::queue_json(d, &std::collections::HashMap::new());
        let sent = served["queue"]["delete_kept"][0]["path"]
            .as_str()
            .expect("the notice rides the queue payload")
            .to_string();
        assert_eq!(sent, win, "the payload must carry the path unaltered");

        let r1 = rev();
        assert!(
            !crate::api::queue::spend_kept_notice(d, r"C:\Users\GS\Downloads\nobody"),
            "spending a path that is not in the ring changes nothing"
        );
        assert_eq!(rev(), r1, "a no-op must not bump");

        assert!(
            crate::api::queue::spend_kept_notice(d, &sent),
            "the served path must match"
        );
        assert_eq!(rev(), r1 + 1, "a real dismiss must bump");
        assert!(
            d.delete_kept.lock_ok().is_empty(),
            "and it must actually leave the ring"
        );
    });
}
