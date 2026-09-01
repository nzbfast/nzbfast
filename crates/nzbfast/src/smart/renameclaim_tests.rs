//! The occupancy WINDOW at `filing.rs`'s five rename doors.
//!
//! Every one of them establishes that a name is free and then renames
//! onto it. `sweep_rename_tests.rs`'s own occupancy cases pin WHICH
//! QUESTION is asked - an entry that holds the name, not a name that
//! resolves - and they are answered identically by the `symlink_metadata`
//! those doors carried until 31 Aug 2026 and by the `create_new` claim
//! they carry now. What separates the two is the GAP behind the answer,
//! and a case that does not race cannot see it: see
//! `crate::renameclaim`'s module note for the measurement and for why
//! the pins here have to be racing ones.
//!
//! One per door, and each was VERIFIED red with ITS OWN door reverted
//! to the `lstat` and green with the others reverted, so no pin here is
//! standing in for a neighbour's.

use super::*;
use crate::renameclaim::never_renames_over_a_neighbour;

/// 300 trials is the sibling's figure (`publish_name_tests.rs`) and it
/// buys ~0.17 s per pin on the dev Mac while racing 90%+ of them.
const TRIALS: usize = 300;

/// `tv_rename` is the canonical door of the five, and the one whose own
/// note carried the stated limit this closes.
#[test]
fn tv_rename_never_files_over_an_episode_created_beside_it() {
    let _steady = trash_globals_steady();
    let dir = scratch("tvrename-race");
    let stem = "My.Show.S01E02.1080p.WEB.x264-TEST";
    let src = dir.join(format!("{stem}.mkv"));
    let target = dir.join("My Show - S01E02 [1080p].mkv");
    never_renames_over_a_neighbour(
        &target,
        TRIALS,
        || std::fs::write(&src, b"the episode this job downloaded").unwrap(),
        || {
            tv_rename(&dir, stem, " [1080p]", &EpisodeTitles::default());
        },
    );
}

/// The de-obfuscation door's VIDEO. Its own arm, not `tv_rename`'s:
/// reverting only this one leaves the pin above green.
#[test]
fn a_nameless_video_never_lands_on_a_name_created_beside_it() {
    let dir = scratch("nameless-race");
    let src = dir.join("n1iY94U6fTpMVY9GPD.mkv");
    let target = dir.join("Supergirl 2026.mkv");
    never_renames_over_a_neighbour(
        &target,
        TRIALS,
        || std::fs::write(&src, b"the feature this job downloaded").unwrap(),
        || {
            rename_nameless_video(&dir, "Supergirl 2026");
        },
    );
}

/// The same door's SIDECAR loop, which is a separate arm with its own
/// claim: a subtitle overwritten in the window is the user's, and the
/// loop discards every result it gets, so nothing else could report it.
#[test]
fn a_nameless_videos_sidecar_never_lands_on_a_name_created_beside_it() {
    let dir = scratch("nameless-sub-race");
    let vid = dir.join("n1iY94U6fTpMVY9GPD.mkv");
    let sub = dir.join("n1iY94U6fTpMVY9GPD.en.srt");
    let target = dir.join("Supergirl 2026.en.srt");
    never_renames_over_a_neighbour(
        &target,
        TRIALS,
        || {
            // The video's own target has to go back too, or the door
            // declines before it reaches the sidecars at all.
            let _ = std::fs::remove_file(dir.join("Supergirl 2026.mkv"));
            std::fs::write(&vid, b"the feature this job downloaded").unwrap();
            std::fs::write(&sub, b"the subtitles this job downloaded").unwrap();
        },
        || {
            rename_nameless_video(&dir, "Supergirl 2026");
        },
    );
}

/// `rename_movie`'s VIDEO arm.
///
/// The job folder is named after `base` already, so `rename_dir` sees
/// `want == out_dir` and returns None - which is what keeps the
/// directory still under the harness while the trials run. The folder
/// ladder is deliberately out of this claim's scope: its source is a
/// DIRECTORY, and `rename(2)` refuses a directory onto any existing
/// entry, so nothing there can be destroyed.
#[test]
fn a_movie_rename_never_lands_on_a_name_created_beside_it() {
    let root = scratch("movie-race");
    let base = "Example Movie (2024) [1080p]";
    let out = root.join(base);
    std::fs::create_dir_all(&out).unwrap();
    let stem = "Example.Movie.2024.1080p.BluRay.x264-FGT";
    let src = out.join(format!("{stem}.mkv"));
    let target = out.join(format!("{base}.mkv"));
    never_renames_over_a_neighbour(
        &target,
        TRIALS,
        || std::fs::write(&src, b"the feature this job downloaded").unwrap(),
        || {
            rename_movie(&root, &out, base);
        },
    );
}

/// `rename_movie`'s SIDECAR loop - its own arm again, and the fourth
/// distinct claim in `filing.rs`.
#[test]
fn a_movie_rename_sidecar_never_lands_on_a_name_created_beside_it() {
    let root = scratch("movie-sub-race");
    let base = "Example Movie (2024) [1080p]";
    let out = root.join(base);
    std::fs::create_dir_all(&out).unwrap();
    let stem = "Example.Movie.2024.1080p.BluRay.x264-FGT";
    let vid = out.join(format!("{stem}.mkv"));
    let sub = out.join(format!("{stem}.en.srt"));
    let target = out.join(format!("{base}.en.srt"));
    never_renames_over_a_neighbour(
        &target,
        TRIALS,
        || {
            let _ = std::fs::remove_file(out.join(format!("{base}.mkv")));
            std::fs::write(&vid, b"the feature this job downloaded").unwrap();
            std::fs::write(&sub, b"the subtitles this job downloaded").unwrap();
        },
        || {
            rename_movie(&root, &out, base);
        },
    );
}

// WHERE THE PLACEHOLDER-REMOVAL ARMS OF THESE FIVE DOORS ARE PINNED,
// which is nowhere, and it is a stated limit rather than an omission.
// Every claim here is followed by a `remove_file` on the rename's error
// arm, and reaching that arm needs a rename that FAILS after a claim
// that SUCCEEDED - so the source has to be something `rename(2)`
// refuses to move onto a file. All five doors filter their candidates
// to `is_file()` first (`tv_rename`'s plan loop, `nameless_video`,
// `rename_movie`'s `videos`, and `sidecars_of`, which reads a list
// already filtered), so a directory source never reaches a claim, and
// nothing else about a plain same-directory rename can be made to fail
// on demand without a seam in production code.
//
// A first cut of this file DID carry such a pin and it was VACUOUS: it
// handed `tv_rename` a directory wearing the episode's posted name,
// passed, and went on passing with the removal arm deleted - because
// the door had skipped the directory and never claimed anything. It is
// deleted rather than weakened.
//
// The arm IS pinned at the one door of the nine where a post-claim
// rename failure is reachable without a seam:
// `serve::tasks::watchfolder`'s `quarantine_rejected` takes the source
// path from its caller, so a file the user deleted between the scan and
// the quarantine is an ordinary shape - see
// `a_quarantine_whose_rename_fails_leaves_no_placeholder_behind`.
