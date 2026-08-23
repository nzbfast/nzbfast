//! `apply_out_umask` tests (#20), moved out of smart.rs bodily (TODO 106).
//! Unix-only, like the function they cover.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn mode(p: &Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

// TODO 149: the guard cleans up on drop; the local copy of scratch()
// this replaces leaked every run's tree.
use super::testkit::scratch;

/// The whole job tree, at both depths, files and directories.
#[test]
fn the_job_tree_gets_the_configured_modes() {
    let root = scratch("tree");
    let out = root.join("downloads");
    let job = out.join("tv").join("Show.S01E01");
    std::fs::create_dir_all(job.join("Subs")).unwrap();
    std::fs::write(job.join("ep.mkv"), b"x").unwrap();
    std::fs::write(job.join("Subs").join("en.srt"), b"x").unwrap();
    for p in [
        &job,
        &job.join("Subs"),
        &job.join("ep.mkv"),
        &job.join("Subs").join("en.srt"),
    ] {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    super::apply_out_umask(&job, Some(&out), 0o002);

    assert_eq!(mode(&job), 0o775, "job dir");
    assert_eq!(mode(&job.join("Subs")), 0o775, "nested dir");
    assert_eq!(mode(&job.join("ep.mkv")), 0o664, "file");
    assert_eq!(mode(&job.join("Subs").join("en.srt")), 0o664, "nested file");
}

/// The reason the parent walk exists: an *arr imports by renaming the
/// job directory out of its parent, and unlink needs write on the
/// PARENT. A version that only did the job's own tree would leave a
/// download that is readable and still cannot be imported.
#[test]
fn the_parents_up_to_the_download_root_are_opened_too() {
    let root = scratch("parents");
    let out = root.join("downloads");
    let job = out.join("tv").join("Show.S01E01");
    std::fs::create_dir_all(&job).unwrap();
    for p in [&out, &out.join("tv")] {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    // Above the download root, and none of our business.
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();

    super::apply_out_umask(&job, Some(&out), 0o002);

    assert_eq!(mode(&out.join("tv")), 0o775, "category dir");
    assert_eq!(mode(&out), 0o775, "download root");
    assert_eq!(
        mode(&root),
        0o700,
        "the walk climbed PAST the download root"
    );
}

/// A sibling under the same parents must be left exactly as it was:
/// the parent walk is non-recursive on purpose.
#[test]
fn a_neighbouring_job_is_not_touched() {
    let root = scratch("sibling");
    let out = root.join("downloads");
    let mine = out.join("tv").join("Mine");
    let theirs = out.join("tv").join("Theirs");
    std::fs::create_dir_all(&mine).unwrap();
    std::fs::create_dir_all(&theirs).unwrap();
    std::fs::write(theirs.join("keep.mkv"), b"x").unwrap();
    std::fs::set_permissions(&theirs, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(
        theirs.join("keep.mkv"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();

    super::apply_out_umask(&mine, Some(&out), 0o002);

    assert_eq!(mode(&theirs), 0o700, "a sibling job was re-moded");
    assert_eq!(mode(&theirs.join("keep.mkv")), 0o600, "a sibling's file");
}

/// 022 is what a container already gives, so choosing it must produce
/// exactly the modes that install has today - the proof that the
/// default-off path and the explicit-022 path agree.
#[test]
fn the_container_default_reproduces_todays_modes() {
    let root = scratch("default");
    let job = root.join("downloads").join("Job");
    std::fs::create_dir_all(&job).unwrap();
    std::fs::write(job.join("a.mkv"), b"x").unwrap();

    super::apply_out_umask(&job, None, 0o022);

    assert_eq!(mode(&job), 0o755);
    assert_eq!(mode(&job.join("a.mkv")), 0o644);
}

/// A symlink inside the job is not followed, and its target keeps its
/// own mode.
///
/// The walk uses `symlink_metadata` for exactly this: `set_permissions`
/// follows links, so a link planted in an archive would otherwise hand
/// whatever it points at the output tree's modes - a file outside the
/// download root entirely, chmodded by a setting about downloads. A link
/// to a DIRECTORY is the sharper half: followed, it would also be pushed
/// onto the walk stack and re-mode everything beneath it.
#[test]
fn a_symlink_is_neither_followed_nor_re_moded() {
    let root = scratch("symlink");
    let out = root.join("downloads");
    let job = out.join("Job");
    std::fs::create_dir_all(&job).unwrap();

    // Two targets outside the job tree, both deliberately tight.
    let outsider = root.join("outsider.conf");
    std::fs::write(&outsider, b"x").unwrap();
    std::fs::set_permissions(&outsider, std::fs::Permissions::from_mode(0o600)).unwrap();
    let elsewhere = root.join("elsewhere");
    std::fs::create_dir_all(elsewhere.join("inner")).unwrap();
    std::fs::write(elsewhere.join("inner").join("f"), b"x").unwrap();
    for p in [&elsewhere, &elsewhere.join("inner")] {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::set_permissions(
        elsewhere.join("inner").join("f"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();

    std::os::unix::fs::symlink(&outsider, job.join("link-to-file")).unwrap();
    std::os::unix::fs::symlink(&elsewhere, job.join("link-to-dir")).unwrap();

    super::apply_out_umask(&job, Some(&out), 0o002);

    assert_eq!(mode(&job), 0o775, "the job's own directory");
    assert_eq!(mode(&outsider), 0o600, "a linked file outside the tree");
    assert_eq!(
        mode(&elsewhere),
        0o700,
        "a linked directory outside the tree"
    );
    assert_eq!(
        mode(&elsewhere.join("inner")),
        0o700,
        "the walk descended THROUGH a symlink"
    );
    assert_eq!(
        mode(&elsewhere.join("inner").join("f")),
        0o600,
        "a file two levels outside the tree was re-moded"
    );
}
