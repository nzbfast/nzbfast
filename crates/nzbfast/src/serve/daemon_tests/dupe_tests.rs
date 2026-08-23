//! Duplicate handling: what `held_as_duplicate` holds, what the discard
//! and fail actions turn a duplicate into, and how the exact scope keeps
//! two releases of one episode - and two non-ASCII titles - apart.
//!
//! A child of daemon_tests, moved out by the size gate (TODO 106). The
//! module is named for its file so size-gate.py's CFG_TEST_MOD resolver
//! still reads it as test code; `use super::*` brings the harness
//! (`with_daemon`, `jv`) and everything they reach.

use super::*;

#[test]
fn held_as_duplicate_requires_pause_and_dupe_priority() {
    with_daemon("dupe", |d| {
        {
            let mut q = d.queue.lock_ok();
            q.push_back(jv(
                "held",
                "held",
                serde_json::json!({"paused": true, "priority": DUPE_PRIORITY}),
            ));
            q.push_back(jv(
                "justpaused",
                "p",
                serde_json::json!({"paused": true, "priority": 0}),
            ));
            q.push_back(jv(
                "justdupe",
                "d",
                serde_json::json!({"paused": false, "priority": DUPE_PRIORITY}),
            ));
        }
        assert!(d.held_as_duplicate("held"));
        assert!(!d.held_as_duplicate("justpaused"));
        assert!(!d.held_as_duplicate("justdupe"));
        assert!(!d.held_as_duplicate("absent"));
    });
}

/// L4: an add that chose to hold against an original must not publish
/// that hold after the original has been deleted.
///
/// `add_lock` serializes adds against each other; deletion takes only
/// the queue lock and never asks the adder. So the collision picked at
/// the top of `enqueue` can be gone by the time the job is pushed, and
/// what lands is an alternative paused at Duplicate priority whose
/// `held_for` names a record nothing will ever fail - and park
/// promotion, the only thing that releases a hold, runs when the
/// original FAILS. The row sits there for good.
///
/// Driven through DUPE_ADMIT_BARRIER because the window is the job
/// build and is zero width without a seam. Both directions: the stale
/// hold is dropped, and a genuine duplicate is still held.
///
/// The release name is this test's alone, and has to be: the seam is
/// keyed by stem because every add in the binary reaches it and the
/// tests run in parallel, so a name another test also adds would put a
/// third waiter on a two-party barrier and hang the run.
#[test]
fn a_hold_is_not_published_against_an_original_deleted_during_admission() {
    with_daemon("dupe-admit-window", |d| {
        let nzb = |seg: &str| {
            format!(
                "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\
                 <file poster=\"x\" date=\"0\" subject=\"&quot;a.bin&quot; yEnc (1/1)\">\
                 <groups><group>g</group></groups><segments>\
                 <segment bytes=\"1000\" number=\"1\">{seg}@x</segment>\
                 </segments></file></nzb>"
            )
        };
        let add = |seg: &str, name: &str| {
            d.enqueue(
                nzb(seg).as_bytes(),
                name,
                "",
                -100,
                None,
                None,
                "test",
                false,
            )
            .map(|e| e.nzo_id)
        };

        // The original, and the control: a second copy added with
        // nothing interfering is still held as an alternative.
        let original = add("one", "Windowed.S03E07.1080p.nzb").unwrap();
        let held = add("two", "Windowed.S03E07.720p.nzb").unwrap();
        assert!(
            d.held_as_duplicate(&held),
            "a genuine duplicate is still held"
        );
        assert_eq!(
            d.queue
                .lock_ok()
                .iter()
                .find(|j| j.lock_ok().nzo_id == held)
                .map(|j| j.lock_ok().held_for.clone()),
            Some(original.clone()),
            "and it points at the original"
        );

        // Now the interleaving: a third add picks the same original,
        // stops with the collision chosen, and the original is deleted
        // out from under it before it publishes.
        let open = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        *crate::serve::daemon::daemon_enqueue::DUPE_ADMIT_BARRIER.lock_ok() = Some((
            "Windowed.S03E07.2160p".to_string(),
            open.clone(),
            release.clone(),
        ));

        let d2 = d.clone();
        let nzb2 = nzb("three");
        let adder = std::thread::spawn(move || {
            d2.enqueue(
                nzb2.as_bytes(),
                "Windowed.S03E07.2160p.nzb",
                "",
                -100,
                None,
                None,
                "test",
                false,
            )
            .map(|e| e.nzo_id)
        });

        // The collision is chosen and the job has not published.
        open.wait();
        d.queue.lock_ok().retain(|j| j.lock_ok().nzo_id != original);
        release.wait();
        let late = adder
            .join()
            .expect("add thread")
            .expect("the add is accepted");
        *crate::serve::daemon::daemon_enqueue::DUPE_ADMIT_BARRIER.lock_ok() = None;

        // It queued normally: nothing is left to fail, so a hold here
        // would never be released.
        assert!(
            !d.held_as_duplicate(&late),
            "the add was admitted against a record that no longer exists"
        );
        let g = d
            .queue
            .lock_ok()
            .iter()
            .find(|j| j.lock_ok().nzo_id == late)
            .expect("the late add joined the queue")
            .clone();
        let g = g.lock_ok();
        assert!(!g.paused, "held paused against a deleted original");
        assert!(
            g.held_for.is_empty(),
            "held_for still names {}, which is gone",
            g.held_for
        );
        // The identity is untouched - only the hold went (the alias arm
        // and promotion both still key off dupe_key).
        assert!(
            g.dupe_key.is_some(),
            "the job keeps its identity either way"
        );
    });
}

/// §129 2d: the dupe_action setting decides what a duplicate add
/// becomes - held (default), refused, or filed to history as Failed -
/// and allow_dupe (the wall's asked-and-said-yes) bypasses all three.
#[test]
fn dupe_action_discard_and_fail_change_what_a_duplicate_becomes() {
    with_daemon("dupeact", |d| {
        let nzb = |seg: &str| {
            format!(
                "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\
                 <file poster=\"x\" date=\"0\" subject=\"&quot;a.bin&quot; yEnc (1/1)\">\
                 <groups><group>g</group></groups><segments>\
                 <segment bytes=\"1000\" number=\"1\">{seg}@x</segment>\
                 </segments></file></nzb>"
            )
        };
        let add = |seg: &str, name: &str, allow: bool| {
            d.enqueue(
                nzb(seg).as_bytes(),
                name,
                "",
                -100,
                None,
                None,
                "test",
                allow,
            )
            .map(|e| e.nzo_id)
        };
        // A name with a derivable identity (SxxEyy) so dupe_key exists.
        add("one", "Show.S01E02.1080p.nzb", false).unwrap();
        // Default: held paused as an ALTERNATIVE.
        let held = add("two", "Show.S01E02.720p.nzb", false).unwrap();
        assert!(d.held_as_duplicate(&held));
        // discard: the add is refused and nothing joins the queue.
        *d.dupe_action.lock_ok() = "discard".into();
        let e = add("three", "Show.S01E02.2160p.nzb", false).unwrap_err();
        assert!(e.to_string().contains("discarded"), "{e}");
        assert_eq!(d.queue.lock_ok().len(), 2);
        // fail: filed straight to history as Failed; queue untouched.
        *d.dupe_action.lock_ok() = "fail".into();
        let failed = add("four", "Show.S01E02.480p.nzb", false).unwrap();
        assert_eq!(d.queue.lock_ok().len(), 2);
        {
            let h = d.history.lock_ok();
            let j = h
                .iter()
                .find(|j| j.lock_ok().nzo_id == failed)
                .expect("filed to history")
                .clone();
            let g = j.lock_ok();
            assert_eq!(g.state, JobState::Failed);
            assert!(g.fail_message.contains("duplicate"), "{}", g.fail_message);
        }
        // allow_dupe bypasses whatever the setting says.
        let ok = add("five", "Show.S01E02.HDR.nzb", true).unwrap();
        assert!(!d.held_as_duplicate(&ok));
        assert_eq!(d.queue.lock_ok().len(), 3);
    });
}

/// #41: dupe_scope = "exact" narrows what collides. A different release
/// of the same episode (an *arr quality upgrade) is not a duplicate and
/// downloads normally; a re-add of the same release name still is, even
/// across separator styles. "smart" (the default) keeps the identity
/// match - pinned above.
#[test]
fn dupe_scope_exact_lets_a_different_release_of_the_same_episode_through() {
    with_daemon("dupescope", |d| {
        let nzb = |seg: &str| {
            format!(
                "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\
                 <file poster=\"x\" date=\"0\" subject=\"&quot;a.bin&quot; yEnc (1/1)\">\
                 <groups><group>g</group></groups><segments>\
                 <segment bytes=\"1000\" number=\"1\">{seg}@x</segment>\
                 </segments></file></nzb>"
            )
        };
        let add = |seg: &str, name: &str| {
            d.enqueue(
                nzb(seg).as_bytes(),
                name,
                "",
                -100,
                None,
                None,
                "test",
                false,
            )
            .map(|e| e.nzo_id)
        };
        *d.dupe_scope.lock_ok() = "exact".into();
        add("one", "Show.S01E02.1080p.WEB-DL.x264-Poke.nzb").unwrap();
        // Same episode, different release: not a duplicate under "exact".
        let upgrade = add("two", "Show.S01E02.1080p.HEVC.x265-MeGusta.nzb").unwrap();
        assert!(!d.held_as_duplicate(&upgrade));
        // Same release re-sent, different separators: still caught.
        let resend = add("three", "Show S01E02 1080p WEB-DL x264-Poke.nzb").unwrap();
        assert!(d.held_as_duplicate(&resend));
        // Back to "smart": identity collides again.
        *d.dupe_scope.lock_ok() = "smart".into();
        let held = add("four", "Show.S01E02.2160p.nzb").unwrap();
        assert!(d.held_as_duplicate(&held));
    });
}

/// Codex sweep K, 13 Aug 2026: admission and promotion asked different
/// questions. Under `dupe_scope = "exact"` a different release of the
/// same episode is admitted and runs; when it failed, `park` promoted
/// held rows by the shared EPISODE key - including one held against a
/// completed original that is still sitting in history. The user got a
/// second copy of something they already had.
#[test]
fn an_exact_mode_failure_does_not_release_another_releases_hold() {
    with_daemon("dupe-promote", |d| {
        let nzb = |seg: &str| {
            format!(
                "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\
                 <file poster=\"x\" date=\"0\" subject=\"&quot;a.bin&quot; yEnc (1/1)\">\
                 <groups><group>g</group></groups><segments>\
                 <segment bytes=\"1000\" number=\"1\">{seg}@x</segment>\
                 </segments></file></nzb>"
            )
        };
        let add = |seg: &str, name: &str| {
            d.enqueue(
                nzb(seg).as_bytes(),
                name,
                "",
                -100,
                None,
                None,
                "test",
                false,
            )
            .map(|e| e.nzo_id)
            .unwrap()
        };
        *d.dupe_scope.lock_ok() = "exact".into();
        // A: completed, in history.
        let a = add("k1", "Show.S05E05.1080p.WEB-DL.x264-Poke.nzb");
        let ja = d.queue_job(&a).unwrap();
        {
            let mut g = ja.lock_ok();
            g.state = JobState::Completed;
        }
        d.queue.lock_ok().retain(|j| j.lock_ok().nzo_id != a);
        d.history.lock_ok().push(ja);

        // B: a DIFFERENT release of the same episode - admitted under
        // exact, and it runs.
        let b = add("k2", "Show.S05E05.2160p.HEVC.x265-MeGusta.nzb");
        assert!(!d.held_as_duplicate(&b));
        // C: a re-send of A's release - held, against A.
        let c = add("k3", "Show S05E05 1080p WEB-DL x264-Poke.nzb");
        assert!(d.held_as_duplicate(&c));

        // B fails. Its failure says nothing about A, which is still
        // completed, so C must stay held.
        let jb = d.queue_job(&b).unwrap();
        {
            let mut g = jb.lock_ok();
            g.state = JobState::Failed;
        }
        d.park_gen(jb, None);
        assert!(
            d.held_as_duplicate(&c),
            "C was held against a COMPLETED original, not against B"
        );
        assert!(
            d.history
                .lock_ok()
                .iter()
                .any(|j| j.lock_ok().nzo_id == a && j.lock_ok().state == JobState::Completed),
            "the original is still completed"
        );
    });
}

/// Codex sweep J, 13 Aug 2026: the exact identity was built with an
/// ASCII-only filter, so every non-Latin letter became a space. Two
/// DIFFERENT CJK titles sharing a tag tail reduced to the same key and
/// the second was held as a duplicate of the first, while a wholly
/// non-ASCII name reduced to the empty string - no identity at all, so
/// a genuine re-send of it was admitted as new.
#[test]
fn exact_identity_keeps_non_ascii_titles_apart() {
    with_daemon("dupe-unicode", |d| {
        let nzb = |seg: &str| {
            format!(
                "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\
                 <file poster=\"x\" date=\"0\" subject=\"&quot;a.bin&quot; yEnc (1/1)\">\
                 <groups><group>g</group></groups><segments>\
                 <segment bytes=\"1000\" number=\"1\">{seg}@x</segment>\
                 </segments></file></nzb>"
            )
        };
        let add = |seg: &str, name: &str| {
            d.enqueue(
                nzb(seg).as_bytes(),
                name,
                "",
                -100,
                None,
                None,
                "test",
                false,
            )
            .map(|e| e.nzo_id)
            .unwrap()
        };
        *d.dupe_scope.lock_ok() = "exact".into();
        let first = add("u1", "電影甲.2024.1080p.WEB-DL.x264-GRP.nzb");
        assert!(!d.held_as_duplicate(&first));
        // A different film, same year and tags: not the same release.
        let other = add("u2", "電影乙.2024.1080p.WEB-DL.x264-GRP.nzb");
        assert!(
            !d.held_as_duplicate(&other),
            "distinct titles must not share an exact identity"
        );
        // …and the same one re-sent IS caught, which needs the name to
        // have had a nonempty identity in the first place.
        let all_cjk = add("u3", "電影丙.nzb");
        assert!(!d.held_as_duplicate(&all_cjk));
        let resend = add("u4", "電影丙.nzb");
        assert!(
            d.held_as_duplicate(&resend),
            "an all-letter non-ASCII name must still have an identity"
        );
    });
}
