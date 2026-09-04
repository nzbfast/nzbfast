//! Which naming layer `finalize_names` actually picks (TODO 142 /
//! issue #32).
//!
//! `smart::nzbname` proves what the rename does to a directory; this
//! proves the daemon reaches it, that a category can allow or disallow
//! it on its own, and - the half that is easy to get wrong - that the
//! metadata renamer then does NOT also run.

use super::super::*;

pub fn with_daemon(name: &str, f: impl FnOnce(&Arc<Daemon>, &std::path::Path)) {
    let dir = std::env::temp_dir().join(format!("nzbfast-nzbname-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let d = super::super::testutil::test_daemon(&dir);
    let out = dir.join("out");
    std::fs::create_dir_all(&out).expect("create out root");
    *d.out_root.write_ok() = out.clone();
    f(&d, &out);
    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A finished movie job in `cat`, named `name`, one feature plus the
/// furniture that must survive whatever we decide to call it.
///
/// Sizes are a thousandth of the release they stand for, for the reason
/// `smart::nzbname_tests::file` gives: only the ranking is read, and a
/// multi-gigabyte `set_len` is a real allocation on NTFS, not a hole.
fn finished(out_root: &std::path::Path, cat: &str, name: &str) -> std::path::PathBuf {
    let dir = out_root.join(cat).join(name);
    std::fs::create_dir_all(&dir).unwrap();
    let mk = |n: &str, len: u64| {
        std::fs::File::create(dir.join(n))
            .unwrap()
            .set_len(len)
            .unwrap();
    };
    mk(&format!("{name}.mkv"), 4_000_000);
    mk("sample.mkv", 30_000);
    mk(&format!("{name}.en.srt"), 60);
    dir
}

fn leaf(p: &std::path::Path) -> String {
    p.file_name().unwrap().to_string_lossy().into_owned()
}

fn entries(dir: &std::path::Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// The posted name a user would recognise as "what the release is
/// called", and which `movie_name` is happy to rewrite.
const POSTED: &str = "Example Movie 2024 1080p BluRay-GRP";

fn run(d: &Arc<Daemon>, dir: &std::path::Path, cat: &str) -> Finalized {
    crate::naming::finalize_names(
        d,
        dir,
        &FinalizeJob {
            name: POSTED,
            cat,
            tv_sort: false,
            post_year: 2024,
        },
    )
}

#[test]
fn off_by_default_the_metadata_renamer_still_owns_the_name() {
    with_daemon("default", |d, out| {
        let dir = finished(out, "movies", POSTED);
        let done = run(d, &dir, "movies");
        let moved = done.moved.expect("the movie renamer renames the folder");
        assert_eq!(leaf(&moved), "Example Movie 2024 1080p");
        assert!(
            entries(&moved).contains(&"Example Movie 2024 1080p.mkv".to_string()),
            "{:?}",
            entries(&moved)
        );
    });
}

#[test]
fn the_global_switch_sources_the_name_from_the_nzb_instead() {
    with_daemon("global", |d, out| {
        d.rename.from_nzb.store(true, Ordering::Relaxed);
        let dir = finished(out, "movies", POSTED);
        let done = run(d, &dir, "movies");
        // The job folder is ALREADY the .nzb name here - that is how
        // `enqueue` built it - so the honest answer is "nothing moved",
        // and the visible change is that the metadata renamer did not
        // move it either.
        assert_eq!(done.moved, None);
        assert!(dir.is_dir(), "the folder keeps the name it was added under");
        assert_eq!(
            entries(&dir),
            vec![
                "Example Movie 2024 1080p BluRay-GRP.en.srt",
                "Example Movie 2024 1080p BluRay-GRP.mkv",
            ],
            "the feature already wore the .nzb name; the subtitle keeps its own"
        );
        assert_eq!(
            done.suffix, "",
            "filing wrote no quality tail, so none may be recorded"
        );
        assert_eq!(done.filed_title, "");
    });
}

/// The rename with something to actually do: the folder was not the
/// .nzb name (an *arr's `nzbname=`, a hook rename, a collision) and the
/// payload inside carries the poster's name.
#[test]
fn the_folder_and_the_main_file_take_the_nzb_name() {
    with_daemon("apply", |d, out| {
        d.rename.from_nzb.store(true, Ordering::Relaxed);
        let dir = finished(out, "movies", "1fRbH6e0eX8v5hv7fSyXgBb");
        let moved = run(d, &dir, "movies").moved.expect("folder renamed");
        assert_eq!(leaf(&moved), POSTED);
        assert_eq!(
            entries(&moved),
            vec![
                "1fRbH6e0eX8v5hv7fSyXgBb.en.srt",
                "Example Movie 2024 1080p BluRay-GRP.mkv",
            ],
            "only the biggest payload file is renamed; the subtitle keeps its own name"
        );
    });
}

#[test]
fn a_category_may_disallow_it_while_the_global_switch_is_on() {
    with_daemon("catoff", |d, out| {
        d.rename.from_nzb.store(true, Ordering::Relaxed);
        d.cat_meta.lock_ok().insert(
            "movies".into(),
            CatMeta {
                nzb_name: Some(false),
                ..Default::default()
            },
        );
        assert!(!crate::naming::name_from_nzb(d, "movies"));
        assert!(
            crate::naming::name_from_nzb(d, "tv"),
            "an unlisted category follows the global"
        );

        let dir = finished(out, "movies", POSTED);
        let moved = run(d, &dir, "movies")
            .moved
            .expect("back to the movie renamer");
        assert_eq!(leaf(&moved), "Example Movie 2024 1080p");
    });
}

#[test]
fn a_category_may_allow_it_while_the_global_switch_is_off() {
    with_daemon("caton", |d, out| {
        d.cat_meta.lock_ok().insert(
            "movies".into(),
            CatMeta {
                nzb_name: Some(true),
                ..Default::default()
            },
        );
        assert!(crate::naming::name_from_nzb(d, "movies"));
        assert!(!crate::naming::name_from_nzb(d, "tv"));

        let dir = finished(out, "movies", "1fRbH6e0eX8v5hv7fSyXgBb");
        let moved = run(d, &dir, "movies").moved.expect("folder renamed");
        assert_eq!(leaf(&moved), POSTED);
    });
}

/// Season filing decides a directory SHAPE, and half-applying it would
/// produce a tree nothing can import. It outranks the .nzb name.
#[test]
fn season_filing_outranks_it() {
    with_daemon("tvsort", |d, out| {
        d.rename.from_nzb.store(true, Ordering::Relaxed);
        let name = "Example Show S01E02 1080p WEB-GRP";
        let dir = finished(out, "tv", name);
        let done = crate::naming::finalize_names(
            d,
            &dir,
            &FinalizeJob {
                name,
                cat: "tv",
                tv_sort: true,
                post_year: 2024,
            },
        );
        let moved = done.moved.expect("season-filed");
        assert!(
            moved.ends_with("Example Show/Season 01"),
            "{}",
            moved.display()
        );
        assert!(
            entries(&moved).contains(&"Example Show - S01E02 1080p.mkv".to_string()),
            "{:?}",
            entries(&moved)
        );
    });
}
