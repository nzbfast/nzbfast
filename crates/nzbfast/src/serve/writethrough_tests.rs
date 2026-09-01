//! TODO 317 (GitHub #67) unit rigs: writing straight into a category's
//! destination instead of moving into it at completion.
//!
//! WHAT THIS BOX CAN AND CANNOT EXERCISE, said plainly rather than left
//! for a reader to assume from a green run. The whole point of the
//! feature is a destination on a DIFFERENT FILESYSTEM - that is what
//! makes the completion move a real copy-then-delete and what makes the
//! double-occupancy window exist - and a second filesystem is not
//! constructible portably from a test. So every case below uses two
//! directories on ONE volume, which pins the PATH ALGEBRA and the
//! decisions (which root, no move owed, no early publish, what a retry
//! does) and pins NOTHING about cross-device behaviour. That is the
//! same limit `mover/lane_tests.rs` states about its own lane keys, and
//! it is the honest one: the arithmetic below is device-independent,
//! and the copy it removes is not measurable here.
//!
//! The one property that carries all the way across a device boundary
//! is stated as a test anyway, because it is checkable as an identity:
//! a write-through job's `out_dir` is EXACTLY the directory the mover
//! would have moved it to. Everything downstream - the mover, §296's
//! early publish, the recategorize path - is then agreeing with one
//! answer rather than deriving a second.

use super::*;
use crate::serve::testutil::test_daemon;

fn scratch(name: &str) -> crate::testscratch::ScratchDir {
    crate::testscratch::ScratchDir::attach(&std::env::temp_dir().join(format!(
        "nzbfast-wt-{}-{name}-{:?}",
        std::process::id(),
        std::thread::current().id()
    )))
}

/// A daemon with `nas` as the destination for `cat`, and write-through
/// armed the way the caller asks for it.
fn armed(dir: &Path, cat: &str, nas: &Path, global: bool) -> Arc<Daemon> {
    let d = test_daemon(dir);
    *d.move_completed_cats.write_ok() = vec![(cat.to_string(), nas.to_path_buf())];
    if global {
        d.write_through.store(true, Ordering::Relaxed);
    } else {
        *d.write_through_cats.lock_ok() = vec![cat.to_string()];
    }
    d
}

/// Both halves of the opt-in reach the same answer, and NEITHER of them
/// reaches it without a destination to reach it about. That last part
/// is the one worth pinning: `write_through_cats` is a bare name list,
/// so a rule can legitimately name a category that has no destination
/// configured yet (the two settings are edited in either order), and it
/// must mean nothing rather than something.
#[test]
fn the_opt_in_needs_both_a_destination_and_a_rule() {
    let s = scratch("optin");
    let nas = s.join("nas");
    for global in [true, false] {
        let d = armed(&s.join("d"), "tv", &nas, global);
        assert!(d.writes_through("tv"), "global={global}");
        assert!(
            !d.writes_through("movies"),
            "global={global}: a category with no destination cannot write through, \
             even under the global switch"
        );
    }
    // A rule naming a category nobody has configured a destination for.
    let d = test_daemon(&s.join("bare"));
    *d.write_through_cats.lock_ok() = vec!["tv".into()];
    assert!(
        !d.writes_through("tv"),
        "a rule with nowhere to write to is inert"
    );
    // ...and the global switch alone, with no destination anywhere.
    let d = test_daemon(&s.join("noglobal"));
    d.write_through.store(true, Ordering::Relaxed);
    assert!(!d.writes_through("tv"));
    assert!(!d.writes_through(""));
}

/// THE identity the whole feature rests on: where a write-through job
/// downloads is exactly where the mover would have moved it.
///
/// Asserted through `move_dest_for` - the mover's own function, not a
/// second spelling of its rule - so a change to the destination layout
/// moves both sides together or fails here. Four shapes, because they
/// are the four the relative path is computed differently for: a
/// per-category destination (the category level is dropped), the global
/// destination (it is kept), the empty category, and a category
/// carrying a `cat_meta.dir` rename, which is the shape that parts a
/// hand-derived root from the real one.
#[test]
fn a_write_through_job_lands_exactly_where_the_mover_would_have_put_it() {
    let s = scratch("identity");
    let nas = s.join("nas");

    // (a) per-category override.
    let d = armed(&s.join("a"), "tv", &nas, false);
    let normal = d.base_out_dir("tv", "Some.Release");
    assert_eq!(
        d.write_through_root("tv").unwrap().join("Some.Release"),
        d.move_dest_for(&normal, "tv").unwrap()
    );
    assert_eq!(
        nas.join("Some.Release"),
        d.move_dest_for(&normal, "tv").unwrap()
    );

    // (b) the GLOBAL destination, which keeps the category component.
    let d = test_daemon(&s.join("b"));
    *d.move_completed.write_ok() = Some(nas.clone());
    d.write_through.store(true, Ordering::Relaxed);
    let normal = d.base_out_dir("tv", "Some.Release");
    assert_eq!(
        d.write_through_root("tv").unwrap().join("Some.Release"),
        d.move_dest_for(&normal, "tv").unwrap()
    );
    assert_eq!(
        nas.join("tv").join("Some.Release"),
        d.move_dest_for(&normal, "tv").unwrap()
    );

    // (c) the empty category, which names no level at all.
    let normal = d.base_out_dir("", "Some.Release");
    assert_eq!(
        d.write_through_root("").unwrap().join("Some.Release"),
        d.move_dest_for(&normal, "").unwrap()
    );
    assert_eq!(
        nas.join("Some.Release"),
        d.move_dest_for(&normal, "").unwrap()
    );

    // (d) a `cat_meta.dir` rename under a per-category destination. The
    // rename is a component of the RELATIVE path, and only
    // `move_dest_for` knows the rule for when the category level comes
    // off it - so this is the shape a second derivation gets wrong.
    let d = armed(&s.join("d"), "tv", &nas, false);
    d.cat_meta.lock_ok().insert(
        "tv".into(),
        crate::serve::daemon::CatMeta {
            dir: "anime".into(),
            ..Default::default()
        },
    );
    let normal = d.base_out_dir("tv", "Some.Release");
    assert_eq!(d.out_dir().join("anime").join("Some.Release"), normal);
    assert_eq!(
        d.write_through_root("tv").unwrap().join("Some.Release"),
        d.move_dest_for(&normal, "tv").unwrap(),
    );
    assert_eq!(
        nas.join("anime").join("Some.Release"),
        d.move_dest_for(&normal, "tv").unwrap()
    );
}

/// Off by default, and a category with a destination but no rule keeps
/// today's behaviour exactly: it downloads under the download root and
/// owes the mover a visit. This is the regression guard for the whole
/// feature being opt-in - TODO 317's own reason for that is that
/// write-through onto a network share pays per-write latency for the
/// entire download, which nobody has measured.
#[test]
fn nothing_writes_through_until_somebody_asks_for_it() {
    let s = scratch("default");
    let nas = s.join("nas");
    let d = test_daemon(&s.join("d"));
    *d.move_completed_cats.write_ok() = vec![("tv".into(), nas.clone())];
    assert!(!d.writes_through("tv"));
    assert_eq!(None, d.write_through_root("tv"));
    assert_eq!(
        d.out_dir().join("tv").join("Some.Release"),
        d.base_out_dir("tv", "Some.Release"),
        "an un-opted category downloads where it always did"
    );
    assert!(
        d.move_destination_configured("tv"),
        "...and still owes the move it always did"
    );
}

/// A write-through job owes the mover NOTHING, and the gate is the
/// job's own record rather than the live setting.
///
/// The second half is the one with teeth. Turn the setting off while a
/// job is running and re-read it at completion, and the job is handed to
/// a mover whose relative path is `strip_prefix(out_dir())` - which a
/// destination-side `out_dir` does not match. It would fall back to
/// `category/<folder>` and relocate the payload into a folder underneath
/// itself. So the record has to survive the setting.
#[test]
fn the_move_is_owed_by_the_record_and_not_by_the_setting() {
    let s = scratch("gate");
    let nas = s.join("nas");
    let d = armed(&s.join("d"), "tv", &nas, false);
    // The live setting still says "tv has a destination" - that is what
    // `move_pending` used to be computed from, on its own.
    assert!(d.move_destination_configured("tv"));
    // Turned off mid-job, which is exactly the case the record exists
    // for: the destination is still configured, so a re-read would say
    // "owed", and the job is already sitting in it.
    *d.write_through_cats.lock_ok() = Vec::new();
    assert!(!d.writes_through("tv"));
    assert!(
        d.move_destination_configured("tv"),
        "the destination did not go away - only the opt-in did, which is \
         why re-deriving the answer at completion would move the payload \
         into a folder beneath itself"
    );
}

/// A write-through job's `out_dir` is deliberately OUTSIDE the download
/// root, and the retry path used to read exactly that as "this job
/// targets a download folder that is no longer configured" - refiling it
/// back into the download root and throwing away its journal and its
/// progress on an ordinary failed retry.
///
/// Pinned as the two answers `retry_job`'s `stale` test is built on,
/// because the test itself needs a whole job and a runtime: a path under
/// the category's destination is NOT stale, and one under neither root
/// is.
#[test]
fn a_destination_side_path_is_not_a_stale_download_folder() {
    let s = scratch("stale");
    let nas = s.join("nas");
    let d = armed(&s.join("d"), "tv", &nas, false);
    let mine = d.write_through_root("tv").unwrap().join("Some.Release");
    let stale = |cur: &Path| {
        !cur.starts_with(d.out_dir())
            && !d
                .move_dest_root("tv")
                .is_some_and(|(root, _)| cur.starts_with(&root))
    };
    assert!(
        !stale(&mine),
        "a job sitting in its own destination is where it belongs"
    );
    assert!(
        !stale(&d.out_dir().join("tv").join("Some.Release")),
        "and so is one that predates the opt-in"
    );
    assert!(
        stale(&s.join("some-unplugged-drive").join("Some.Release")),
        "a path under neither root is the case the check exists for"
    );
    // Dropping the DESTINATION, not the opt-in, is what strands the
    // path - and it should, because there is then nothing saying the
    // folder is one of ours.
    *d.move_completed_cats.write_ok() = Vec::new();
    assert!(stale(&mine));
}

/// The record round-trips. It is persisted for the reason
/// `Job::write_through` gives - a restart cannot re-derive it, because
/// the setting may have moved in between - and a record written before
/// TODO 317 reads as false, which is true of all of them.
#[test]
fn the_write_through_record_survives_a_restart() {
    let j = crate::serve::tests_jobs::job(serde_json::json!({
        "nzo_id": "SABnzbd_nzo_wt1",
        "name": "Some.Release",
        "nzb_path": "/tmp/nzbfast-wt/job.nzb",
        "out_dir": "/tmp/nzbfast-wt/Some.Release",
        "state": "Completed",
        "write_through": true,
    }));
    assert!(j.write_through);
    let back = crate::serve::job::job_from_json(&crate::serve::job::job_json(&j)).unwrap();
    assert!(
        back.write_through,
        "the whole point is that a restart still knows"
    );

    let old = crate::serve::tests_jobs::job(serde_json::json!({
        "nzo_id": "SABnzbd_nzo_wt2",
        "name": "Some.Release",
        "nzb_path": "/tmp/nzbfast-wt/job.nzb",
        "out_dir": "/tmp/nzbfast-wt/Some.Release",
        "state": "Completed",
    }));
    assert!(
        !old.write_through,
        "a record written before TODO 317 downloaded into the download folder"
    );
}

/// The category-name list is parsed the way the enqueue path spells a
/// category, or a rule would silently match nothing: `sanitize_filename`
/// maps `/` to `_`, so `movies/anime` is the folder `movies_anime` and
/// the rule has to say the same. Duplicates and empties are dropped
/// rather than refused - the only thing a refusal could protect here is
/// a typo, and it would take the usable names down with it.
#[test]
fn the_category_rule_list_is_spelled_the_way_a_category_is() {
    use crate::serve::fsutil::parse_cat_names;
    assert_eq!(
        vec!["tv".to_string(), "movies".to_string()],
        parse_cat_names(" tv , movies ")
    );
    assert_eq!(
        vec!["tv".to_string()],
        parse_cat_names("tv;;tv,"),
        "an empty item is skipped BEFORE sanitizing - `sanitize_filename` \
         answers an empty string with `unnamed`, so a trailing comma would \
         otherwise mint a rule for a category nobody typed"
    );
    assert!(parse_cat_names("   ").is_empty());
    assert!(parse_cat_names("").is_empty());
    assert_eq!(
        vec![nzbkit::disk::sanitize_filename("movies/anime")],
        parse_cat_names("movies/anime"),
        "sanitized here exactly as enqueue sanitizes it, or the rule matches nothing"
    );
}

/// End to end through `enqueue`: the job really is created in the
/// destination, its record says so, and the un-opted category beside it
/// is untouched.
///
/// This is the one case that exercises the enqueue path rather than the
/// arithmetic under it, and it is what a reader should look at first.
/// The two directories are on ONE volume - see this file's header for
/// why, and for what that does and does not prove.
#[test]
fn enqueue_creates_a_write_through_job_in_the_destination() {
    let s = scratch("enqueue");
    let nas = s.join("nas");
    let d = armed(&s.join("d"), "tv", &nas, false);
    // A second destination with NO rule, so the same daemon carries one
    // category of each and the un-opted one is a live control rather
    // than a separate fixture.
    d.move_completed_cats
        .write_ok()
        .push(("movies".into(), s.join("nas2")));

    let nzb = "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\
               <file poster=\"x\" date=\"0\" subject=\"&quot;a.bin&quot; yEnc (1/1)\">\
               <groups><group>g</group></groups><segments>\
               <segment bytes=\"1000\" number=\"1\">wt1@x</segment>\
               </segments></file></nzb>";
    for (cat, want, through) in [
        ("tv", nas.join("Write.Through.Test"), true),
        (
            "movies",
            d.out_dir().join("movies").join("Write.Through.Test"),
            false,
        ),
    ] {
        d.enqueue(
            nzb.as_bytes(),
            "Write.Through.Test.nzb",
            cat,
            0,
            None,
            None,
            "test",
            false,
        )
        .unwrap_or_else(|e| panic!("enqueue {cat}: {e}"));
        let job = d
            .queue
            .lock_ok()
            .iter()
            .find(|j| j.lock_ok().category == cat)
            .cloned()
            .unwrap_or_else(|| panic!("no queued job in {cat}"));
        let g = job.lock_ok();
        assert_eq!(want, g.out_dir, "category {cat}");
        assert_eq!(through, g.write_through, "category {cat}");
    }

    // The write-through job's directory is on the destination side and
    // the other one is not - which is the whole ask in one line, and is
    // also the property the retry path's `stale` test now honours.
    let tv = nas.join("Write.Through.Test");
    assert!(!tv.starts_with(d.out_dir()));
    // Nothing is on disk yet at either end, and that is unchanged
    // rather than a consequence of this feature: a job directory is
    // created at DOWNLOAD time, which is what `DEFAULT_CATS`'s own note
    // means by "categories cost nothing until a job uses one". Pinned
    // so a later reader does not take the empty destination for a
    // write-through that failed.
    assert!(!tv.exists());
    assert!(!nas.exists());
}
