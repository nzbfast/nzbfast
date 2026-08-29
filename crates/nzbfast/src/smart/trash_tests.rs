//! Trash / recoverable-delete tests, moved out of smart.rs bodily
//! (TODO 106). Same child-module pattern as `cleanup_mode_tests`.

/// A removal only claims "recoverable" when the file was FOUND in a
/// Trash afterwards.
///
/// The backend returning Ok is not that claim: macOS has two routes
/// and both can report success while deleting outright, which is how
/// a 14 GB download was reported restorable on 4 Aug when it was
/// gone. This pins the check that catches it - a name that is in no
/// Trash answers false - and the permanent-delete arm, which must
/// never claim `Trashed`.
#[test]
fn a_removal_reports_what_it_actually_did() {
    let dir = std::env::temp_dir().join(format!("nzbfast-removed-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // An opt-out delete is permanent by definition and says so.
    let f = dir.join("plain.bin");
    std::fs::write(&f, b"x").unwrap();
    assert_eq!(
        super::remove_user_file(&f, false).unwrap(),
        super::Removed::Gone,
        "a permanent delete must never report itself recoverable"
    );
    assert!(!f.exists());

    // A path that was never there is gone, not trashed - there is
    // nothing to restore and nothing may promise otherwise.
    assert_eq!(
        super::remove_user_file(&dir.join("never-existed.bin"), true).unwrap(),
        super::Removed::Gone
    );

    // The verification itself: a file sitting in an ordinary
    // directory has not landed in any Trash.
    #[cfg(target_os = "macos")]
    {
        let never = dir.join("nzbfast-not-in-any-trash-9f3a.bin");
        std::fs::write(&never, b"x").unwrap();
        assert!(
            !super::landed_in_a_trash(&never, &super::trash_snapshot(&never)),
            "a file that was never trashed must not read as recoverable"
        );

        // A NAME that was already in the Trash is not evidence about
        // THIS delete. Simulated by putting the would-be match into
        // the before-snapshot: on a `noowners` volume Finder deletes
        // outright and reports success, and a `Movie.mkv` binned
        // last week then made the destroyed one read as restorable.
        if let Some(home) = std::env::var_os("HOME") {
            let root = std::path::PathBuf::from(home).join(".Trash");
            let planted = root.join("nzbfast-stale-trash-probe-4b21.bin");
            if std::fs::create_dir_all(&root).is_ok() && std::fs::write(&planted, b"old").is_ok() {
                let target = dir.join("nzbfast-stale-trash-probe-4b21.bin");
                let before = super::trash_snapshot(&target);
                assert!(
                    !super::landed_in_a_trash(&target, &before),
                    "an entry that was ALREADY in the Trash must not \
                     vouch for a delete that just happened"
                );
                // And a genuinely new arrival still counts.
                assert!(
                    super::landed_in_a_trash(&target, &super::TrashBefore::default()),
                    "a newly arrived entry must still read as recoverable"
                );
                let _ = std::fs::remove_file(&planted);
            }
        }
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
use super::*;

/// Did a file this test just deleted actually reach the Trash, under
/// the name it had? Purges it when it did, so the suite never leaves
/// fixtures in the developer's real Trash. `None` on a platform with no
/// way to look.
///
/// Asked per platform because "the Trash" is three different
/// mechanisms, and the old version of this test assumed one of them:
/// `std::env::var("HOME").unwrap()` joined with `.Trash`. HOME is not
/// set on Windows - USERPROFILE is, which is why the product itself
/// reads that - so the test panicked with `NotPresent` there before it
/// asserted anything, and `~/.Trash` would have been the wrong place to
/// look anyway. Windows has a real recoverable delete: `trash::delete`
/// moves the file to the Recycle Bin, verified on x86-64 Windows, where
/// `os_limited::list()` returns it with its original_parent intact. So
/// this checks the behaviour there rather than gating the test away.
/// `os_limited` covers the freedesktop platforms too, which makes the
/// Linux leg a real assertion instead of the vacuous one it was.
fn still_recoverable(name: &str) -> Option<bool> {
    // macOS: `trash` has no enumeration API there, so read the folder.
    #[cfg(target_os = "macos")]
    {
        let trashed = std::path::PathBuf::from(std::env::var("HOME").expect("HOME on macOS"))
            .join(".Trash")
            .join(name);
        let found = trashed.exists();
        let _ = std::fs::remove_file(&trashed);
        Some(found)
    }
    // Windows' Recycle Bin and the freedesktop trash directories, read
    // through the real thing. The cfg mirrors `trash::os_limited`'s own.
    #[cfg(any(
        target_os = "windows",
        all(
            unix,
            not(target_os = "macos"),
            not(target_os = "ios"),
            not(target_os = "android")
        )
    ))]
    {
        // `expect`, not `.ok()?`: a platform that HAS an enumeration
        // API and cannot answer is a finding, not a reason to skip. We
        // have already asserted the delete succeeded, so the trash
        // exists - swallowing an error here would make the assertion
        // below silently vacuous, which is the failure mode this whole
        // test is guarding against.
        let items = trash::os_limited::list().expect("enumerate the trash");
        let mine: Vec<_> = items.into_iter().filter(|i| i.name == *name).collect();
        let found = !mine.is_empty();
        let _ = trash::os_limited::purge_all(mine);
        Some(found)
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "windows",
        all(
            unix,
            not(target_os = "macos"),
            not(target_os = "ios"),
            not(target_os = "android")
        )
    )))]
    {
        let _ = name;
        None
    }
}

/// Both halves in ONE test, and neither touches the process-global.
///
/// `remove_user_file` takes the flag as an argument now, so the two
/// cases are just two calls: nothing here can flip a sweep running in
/// a parallel test, and nothing here leaves the flag somewhere the
/// tests scheduled after it do not expect (this test used to restore
/// it to TRUE, which turned the Trash ON for the rest of the process
/// and made `sweep_junk_takes_the_emptied_sample_folder_too` fail
/// depending on test order).
#[test]
fn a_junk_delete_is_recoverable_and_the_opt_out_is_not() {
    // This one really does reach the Trash, so it must not overlap a
    // test that latches the Trash off underneath it.
    let _serial = one_trash_test_at_a_time();
    let dir = std::env::temp_dir().join(format!("nzbfast-trash-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // Recoverable: the file leaves the download folder but is still
    // there to be put back. Asserting only that it is GONE would pass
    // just as well for a permanent delete, which is the whole point.
    let name = format!("nzbfast-trash-probe-{}.par2", std::process::id());
    let f = dir.join(&name);
    std::fs::write(&f, b"junk").unwrap();
    remove_user_file(&f, true).expect("trash delete");
    assert!(!f.exists(), "the file must leave the download folder");
    if let Some(found) = still_recoverable(&name) {
        // The file being GONE proves nothing on its own - a permanent
        // delete looks identical from the download folder. This is the
        // assertion that separates the two.
        assert!(
            found,
            "not recoverable: nothing named {name} reached the Trash"
        );
    }

    // Opted out: a real delete, not a silent Trash.
    let name2 = format!("nzbfast-notrash-probe-{}.par2", std::process::id());
    let g = dir.join(&name2);
    std::fs::write(&g, b"junk").unwrap();
    remove_user_file(&g, false).unwrap();
    assert!(!g.exists());
    if let Some(found) = still_recoverable(&name2) {
        assert!(!found, "opt-out still used the Trash");
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// The directory delete behind "delete + files" and the watchlist
/// delete_old upgrade: recoverable moves the WHOLE folder to the
/// Trash as one restorable item, opt-out is a real remove_dir_all,
/// and a directory that never existed is Ok (jobs that never
/// downloaded have no folder).
#[test]
fn a_job_dir_delete_is_recoverable_and_the_opt_out_is_not() {
    let _serial = one_trash_test_at_a_time();
    let root = std::env::temp_dir().join(format!("nzbfast-trashdir-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);

    let name = format!("nzbfast-trashdir-probe-{}", std::process::id());
    let d = root.join(&name);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("payload.mkv"), b"x").unwrap();
    remove_user_dir(&d, true).expect("trash delete");
    assert!(!d.exists(), "the folder must leave the download tree");
    if let Some(found) = still_recoverable(&name) {
        assert!(
            found,
            "not recoverable: nothing named {name} reached the Trash"
        );
    }
    // still_recoverable purges a FILE from the macOS Trash; a folder
    // needs the recursive form or the probe lingers there forever.
    #[cfg(target_os = "macos")]
    if let Ok(home) = std::env::var("HOME") {
        let _ = std::fs::remove_dir_all(std::path::Path::new(&home).join(".Trash").join(&name));
    }

    let name2 = format!("nzbfast-notrashdir-probe-{}", std::process::id());
    let g = root.join(&name2);
    std::fs::create_dir_all(&g).unwrap();
    std::fs::write(g.join("payload.mkv"), b"x").unwrap();
    remove_user_dir(&g, false).unwrap();
    assert!(!g.exists());
    if let Some(found) = still_recoverable(&name2) {
        assert!(!found, "opt-out still used the Trash");
    }

    // A directory that is not there is a finished delete, not an
    // error - remove_job_files runs on jobs that never started.
    remove_user_dir(&root.join("never-existed"), true).unwrap();
    remove_user_dir(&root.join("never-existed"), false).unwrap();

    let _ = std::fs::remove_dir_all(&root);
}

/// macOS's second route, exercised for real: `NSFileManager` must bin
/// a file with no Finder involved, and `trash_delete_bounded` must
/// reach it once the Finder latch is set.
///
/// This is the fix for the live 3 Aug 2026 line, where Finder answered
/// `-10010` for a directory on an external volume and the delete
/// became permanent. Finder failing is not the same as having no
/// Trash, and the volume's own `.Trashes` was there the whole time.
///
/// The latch is process-global and never reset in production, so the
/// test restores it by hand and serializes with the other latch tests.
#[cfg(target_os = "macos")]
#[test]
fn the_volume_trash_takes_over_when_finder_will_not() {
    let _serial = one_trash_test_at_a_time();
    let dir = std::env::temp_dir().join(format!("nzbfast-nsfm-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // Directly first: the route itself has to work before the
    // fall-through to it means anything.
    let name = format!("nzbfast-nsfm-probe-{}.par2", std::process::id());
    let f = dir.join(&name);
    std::fs::write(&f, b"junk").unwrap();
    trash_via_file_manager(&f).expect("NSFileManager must bin a file with no Finder");
    assert!(!f.exists());
    assert_eq!(
        still_recoverable(&name),
        Some(true),
        "NSFileManager did not put {name} anywhere recoverable"
    );

    // Then through the real entry point with Finder latched out, which
    // is the state a -10010 or a headless timeout leaves behind.
    let name2 = format!("nzbfast-nsfm-latched-{}.par2", std::process::id());
    let g = dir.join(&name2);
    std::fs::write(&g, b"junk").unwrap();
    let was_out = finder_is_out();
    FINDER_IS_OUT.store(true, std::sync::atomic::Ordering::Relaxed);
    let r = remove_user_file(&g, true);
    FINDER_IS_OUT.store(was_out, std::sync::atomic::Ordering::Relaxed);
    r.expect("a latched Finder must not stop the delete");
    assert!(!g.exists());
    assert_eq!(
        still_recoverable(&name2),
        Some(true),
        "with Finder out the delete went somewhere unrecoverable"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A scratch path in `$TMPDIR` is never sent to the Trash, and a real
/// download path still is.
///
/// The recoverable route exists to make a wrong guess about the USER's
/// data survivable. `$TMPDIR` holds our own scratch and the test suites'
/// fixtures, so binning it only hands the user junk to empty - and on
/// macOS it misbehaves outright: the Finder call is bounded, whoever owns
/// the scratch dir deletes it while Finder is still working, and Finder
/// puts a modal "-43" on the desktop long after the run that caused it.
/// Every integration test spawns a real `nzbfast` child against a
/// `nzbfast-*` dir in `$TMPDIR`, and none of them are `cfg(test)` in the
/// binary they drive, so this rule is the only thing covering them.
///
/// Pins `path_is_under` rather than `under_temp_dir`, which answers false
/// under `cfg(test)` so the three tests above can still reach the Trash.
/// The `/var` -> `/private/var` case is the one that matters on macOS: a
/// caller holding the uncanonicalized path must not slip past.
#[test]
fn a_temp_path_is_never_worth_the_trash() {
    let tmp = std::env::temp_dir();
    let scratch = tmp.join(format!("nzbfast-tempgate-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).unwrap();
    let f = scratch.join("spent.par2");
    std::fs::write(&f, b"x").unwrap();

    assert!(
        super::path_is_under(&f, &tmp),
        "a file in the scratch dir must read as temp"
    );

    // macOS canonicalizes $TMPDIR to /private/var/folders/... while the
    // same file is equally reachable as /var/folders/... - the symlink
    // must not defeat the check. Built from the file that really exists,
    // because canonicalize only resolves a path that is there; a name
    // that is not falls back to itself by design (see `path_is_under`),
    // and that case cannot exercise the symlink at all.
    #[cfg(target_os = "macos")]
    if let Ok(rest) = f.strip_prefix("/private") {
        let twin = std::path::Path::new("/").join(rest);
        assert!(twin.exists(), "the /var twin of a temp path must resolve");
        assert!(
            super::path_is_under(&twin, &tmp),
            "the /private symlink must not slip a temp path past the gate"
        );
    }

    // A download living somewhere real is untouched by this rule: it is
    // the user's data and the Trash is exactly what it wants.
    assert!(
        !super::path_is_under(std::path::Path::new("/srv/media/downloads/m.mkv"), &tmp),
        "a real download path must still be eligible for the Trash"
    );

    let _ = std::fs::remove_dir_all(&scratch);
}

// No test toggles TRASH any more, deliberately. Turning it on for even
// one assertion turns it on for whatever sweep is running in parallel,
// which empties that test's fixtures into the developer's real Trash.
// The setting itself is one atomic store, and the sweeps now read it
// once at their entry and pass the answer down (see `remove_user_file`).

/// The recoverable-delete DEFAULT must follow what the platform's trash
/// arm can actually do.
///
/// Nothing pinned this predicate before, and it shipped wrong: it said
/// android and iOS had a system trash while `trash_delete_bounded`'s arm
/// for exactly those two can only return `Err`. The route stayed on, so
/// every delete-the-files-too refused, kept the payload and dropped the
/// history row anyway - 40 MB measured on the Android emulator (26 Aug
/// 2026) and 38 MB on iOS (27 Aug 2026), both behind an answer of
/// `{"removed":1,"status":true}`.
///
/// This test reads the HOST's answer, so between the mac dev box and
/// CI's ubuntu runner it covers the two arms of the linux/freebsd
/// carve-out that the Unraid incident bought. The two mobile arms cannot
/// be observed from here at all: they are pinned instead by the
/// `const _: () = assert!(..)` inside that refusing arm, which is
/// evaluated when compiling FOR those targets and was verified to fire
/// when the predicate is put back the way it shipped.
#[test]
fn the_recoverable_default_follows_the_platform_that_has_to_honour_it() {
    let no_trash_here = cfg!(any(target_os = "android", target_os = "ios"));
    assert_eq!(
        super::platform_has_no_system_trash(),
        no_trash_here,
        "the no-system-trash list must name android and iOS, and nothing else"
    );

    // A platform with no trash to move anything into may never default
    // the recoverable route on: the arm behind it can only refuse.
    if super::platform_has_no_system_trash() {
        assert!(
            !super::trash_suits_this_platform(),
            "the route is on for a platform whose trash arm can only refuse"
        );
    }

    // The server carve-out, kept separate because it is a POLICY choice
    // rather than a capability fact, and is the reason a user lost an
    // SSD a directory at a time to `.Trash-<uid>` on Unraid.
    if cfg!(any(target_os = "linux", target_os = "freebsd")) {
        assert!(
            !super::trash_suits_this_platform(),
            "linux and freebsd installs must delete outright unless asked otherwise"
        );
    }

    // macOS and Windows keep the Trash: it is a real, user-visible one
    // that a desktop session empties.
    if cfg!(any(target_os = "macos", target_os = "windows")) {
        assert!(
            super::trash_suits_this_platform(),
            "the desktop platforms must keep their recoverable default"
        );
    }
}
