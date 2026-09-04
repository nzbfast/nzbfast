//! Axis A of the Wave-7 post-settle handoff: which name owns a job once
//! settle has already named its payload.
//!
//! `finalize_names` is the SECOND naming system in this product. It runs
//! after settle on a completed job, and it classifies, sweeps, renames
//! and re-files from `job.name` - the string the .nzb arrived under.
//! Settle names FILES, from the recovery set's own FileDesc packets and
//! a whole-file MD5 pair. When the two disagree, the .nzb won.
//!
//! Two rows come out of that, measured live on 31 Aug 2026 in
//! `research/POST-SETTLE-NAME-AUTHORITY-2026-08-31.md`:
//!
//!   * **W7-05** - a fully obfuscated post's job name is a hash, so it
//!     classifies to `Base::None` and NOTHING fires: no junk sweep, no
//!     folder rename, no quality suffix, however perfectly settle just
//!     named every file inside it.
//!   * **W7-06** - and when the job name DOES classify, its parse
//!     overwrites the proved name outright, on the file and on the
//!     folder, carrying the subtitle sidecar with it. GH #63's
//!     `filedesc_name_is_better` exists to answer exactly this question
//!     one layer down and has zero callers under `serve/`.
//!
//! **W7-08** is here too because it is the same arm: `rename_movie`'s
//! one-video selection declines on a preserved disc tree, that decline
//! is CORRECT, and W7-05 is the first change to arm that arm for a
//! population it never ran over - so the pin belongs in this commit
//! rather than in a later one.

use super::super::*;
use crate::smart::par2_index;

pub fn with_daemon(name: &str, f: impl FnOnce(&Arc<Daemon>, &std::path::Path)) {
    let dir = std::env::temp_dir().join(format!("nzbfast-authority-{name}-{}", std::process::id()));
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

/// An obfuscated job name: a hash, which is what a fully obfuscated
/// post's .nzb is called and what `classify` parses to no kind at all.
const HASHED: &str = "d41d8cd98f00b204e9800998ecf8427e";

/// What settle proved and wrote to disk. Carries a group tag, so the
/// metadata renamer has something to strip and the control below can
/// tell "the proved name won" from "nothing ran".
const PROVED: &str = "Example Movie 2024 1080p BluRay-GRP";

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

/// A finished job directory: the feature settle named, its subtitle, the
/// furniture every sweep exists to remove, and - when `declare` - a
/// recovery set on disk whose FileDesc names the feature. That set is
/// the whole of what makes the name PROVED rather than merely present;
/// `smart::setclaim` reads it at exactly this moment, because the sweep
/// is what deletes the `.par2` afterwards.
fn finished(
    out_root: &std::path::Path,
    job: &str,
    payload: &str,
    declare: bool,
) -> std::path::PathBuf {
    let dir = out_root.join("movies").join(job);
    std::fs::create_dir_all(&dir).unwrap();
    let mk = |n: &str, len: u64| {
        std::fs::File::create(dir.join(n))
            .unwrap()
            .set_len(len)
            .unwrap();
    };
    mk(&format!("{payload}.mkv"), 4_000_000);
    mk(&format!("{payload}.en.srt"), 60);
    mk("rarbg.txt", 40);
    mk("sample.mkv", 30_000);
    if declare {
        std::fs::write(
            dir.join("release.par2"),
            par2_index(0x51, &[(&format!("{payload}.mkv"), 4_000_000)]),
        )
        .unwrap();
    }
    dir
}

fn run(d: &Arc<Daemon>, dir: &std::path::Path, name: &str) -> Finalized {
    crate::naming::finalize_names(
        d,
        dir,
        &FinalizeJob {
            name,
            cat: "movies",
            tv_sort: false,
            post_year: 2024,
        },
    )
}

/// W7-05. The payload is perfectly named and the .nzb is a hash. The
/// job is classifiable - from what settle put on disk - so it is filed
/// under its release name and the furniture goes, exactly as the same
/// directory under its real posted name already was.
///
/// Measured on origin/main before this landed: `moved=None swept=0`,
/// a correctly named movie sitting in a hash-named folder beside
/// `rarbg.txt` and `sample.mkv`.
#[test]
fn an_obfuscated_job_name_is_reclassified_from_what_settle_put_on_disk() {
    with_daemon("w705", |d, out| {
        let dir = finished(out, HASHED, PROVED, true);
        let done = run(d, &dir, HASHED);
        let moved = done
            .moved
            .expect("a job whose payload names itself is a job that can be filed");
        assert_eq!(leaf(&moved), "Example Movie 2024 1080p");
        assert!(
            done.swept > 0,
            "the furniture beside a classifiable payload is furniture: {:?}",
            entries(&moved)
        );
        assert!(!moved.join("rarbg.txt").exists(), "{:?}", entries(&moved));
    });
}

/// The control that keeps the row above from reading as "file every
/// job": when the payload is obfuscated TOO there is nothing on disk to
/// classify from, so the job stays exactly where it was and nothing is
/// deleted beside it.
#[test]
fn a_job_whose_payload_is_also_obfuscated_is_still_left_alone() {
    with_daemon("w705ctl", |d, out| {
        let dir = finished(out, HASHED, "7f3a1c0b9e2d4a68", true);
        let done = run(d, &dir, HASHED);
        assert_eq!(done.moved, None, "nothing on disk names this release");
        assert_eq!(done.swept, 0, "and nothing beside it may be deleted for it");
        assert!(dir.join("rarbg.txt").exists());
    });
}

/// W7-05's safety direction, and the ruling
/// `research/POST-SETTLE-NAME-AUTHORITY-2026-08-31.md` makes explicitly:
/// a DISK-DERIVED classification may arm the folder rename, the quality
/// suffix, `measured_res` and `sweep_junk` - and never
/// `keep_media_only`, which deletes by extension list rather than by a
/// named list and is the one consequence that can take the payload.
///
/// `bonus.xyz` is the discriminator: `keep_media_only` deletes anything
/// that is not media, companion or archive, and `sweep_junk` deletes a
/// NAMED list that has never held `xyz`.
#[test]
fn a_disk_derived_classification_never_arms_the_keep_media_sweep() {
    with_daemon("w705keep", |d, out| {
        d.rename.media_only.store(true, Ordering::Relaxed);
        let dir = finished(out, HASHED, PROVED, true);
        std::fs::File::create(dir.join("bonus.xyz"))
            .unwrap()
            .set_len(9_000)
            .unwrap();
        let done = run(d, &dir, HASHED);
        let moved = done.moved.expect("the folder still gets its release name");
        assert!(
            moved.join("bonus.xyz").exists(),
            "keep-media-only deletes by exclusion and a disk-derived \
             classification may not arm it: {:?}",
            entries(&moved)
        );
        assert!(
            !moved.join("rarbg.txt").exists(),
            "the safer sweep still runs: {:?}",
            entries(&moved)
        );
    });
}

/// W7-06 in its sharpest form: the .nzb names a DIFFERENT FILM, and the
/// payload's name is one a recovery set on disk declares.
///
/// Measured on origin/main before this landed: the folder became
/// `Wrong Film 2019 1080p` and the feature and its subtitle were both
/// renamed to it. Title and year are the two fields nothing downstream
/// ever re-derives - `movie_year` only FILLS an absent year and nothing
/// anywhere re-reads a title - so that damage is permanent.
#[test]
fn a_par2_proved_title_outranks_a_subject_parse_that_names_another_film() {
    with_daemon("w706", |d, out| {
        let dir = finished(out, "Wrong Film 2019 1080p WEB-DL-OTHER", PROVED, true);
        let done = run(d, &dir, "Wrong Film 2019 1080p WEB-DL-OTHER");
        let moved = done.moved.expect("the folder is still filed");
        assert_eq!(
            leaf(&moved),
            "Example Movie 2024 1080p",
            "the set declares the payload; a regex over the subject line does not"
        );
        assert_eq!(
            entries(&moved)
                .into_iter()
                .filter(|n| n.ends_with(".mkv") && n != "sample.mkv")
                .collect::<Vec<_>>(),
            vec!["Example Movie 2024 1080p.mkv"],
        );
    });
}

/// The control that keeps the row above from disabling the metadata
/// renamer for the whole population: nearly every honest movie post has
/// a recovery set declaring its payload, so "the declared name wins"
/// flat would mean the renamer never strips a group tag again. It fires
/// only where the two parses CONTRADICT - on title or on year - and
/// decoration is not a contradiction.
#[test]
fn a_proved_name_that_agrees_still_lets_the_renamer_decorate() {
    with_daemon("w706ctl", |d, out| {
        let dir = finished(out, PROVED, PROVED, true);
        let done = run(d, &dir, PROVED);
        let moved = done.moved.expect("the folder is filed");
        assert_eq!(
            leaf(&moved),
            "Example Movie 2024 1080p",
            "same title, same year - the group tag is the renamer's to strip"
        );
    });
}

/// W7-06's evidence bar, from the other side. A name on disk that NO
/// set declares was produced by whichever tier could name it, and the
/// weakest of those is a parse of the same subject line - so it is not
/// stronger evidence than the job name and may not override it. The
/// house rule the repost table already applies (W7-02): a name that
/// merely LOOKS like a name has not been proved.
#[test]
fn an_undeclared_name_on_disk_does_not_override_the_job_name() {
    with_daemon("w706undecl", |d, out| {
        let dir = finished(out, "Wrong Film 2019 1080p WEB-DL-OTHER", PROVED, false);
        let done = run(d, &dir, "Wrong Film 2019 1080p WEB-DL-OTHER");
        let moved = done.moved.expect("the folder is filed");
        assert_eq!(
            leaf(&moved),
            "Wrong Film 2019 1080p",
            "nothing on disk proved otherwise, so today's answer stands"
        );
    });
}

/// W7-08. `rename_movie`'s one-video arm scans `read_dir(out_dir)`
/// filtered on `is_file()`, so a preserved `VIDEO_TS` tree presents ZERO
/// videos at the root and no file is renamed - while the folder still
/// moves. That is the correct outcome, and W7-05 is the first change to
/// send an obfuscated job down this arm at all, so it is pinned here.
#[test]
fn a_preserved_disc_tree_is_filed_without_renaming_a_single_vob() {
    with_daemon("w708", |d, out| {
        let dir = out.join("movies").join(HASHED);
        std::fs::create_dir_all(dir.join("VIDEO_TS")).unwrap();
        let mk = |rel: &str, len: u64| {
            std::fs::File::create(dir.join(rel))
                .unwrap()
                .set_len(len)
                .unwrap();
        };
        mk("VIDEO_TS/VIDEO_TS.IFO", 12_000);
        mk("VIDEO_TS/VTS_01_1.VOB", 4_000_000);
        mk("VIDEO_TS/VTS_01_2.VOB", 3_000_000);
        std::fs::write(
            dir.join("release.par2"),
            par2_index(0x52, &[("VIDEO_TS/VTS_01_1.VOB", 4_000_000)]),
        )
        .unwrap();
        let done = run(d, &dir, HASHED);
        let root = done.moved.unwrap_or(dir);
        assert_eq!(
            entries(&root.join("VIDEO_TS")),
            vec!["VIDEO_TS.IFO", "VTS_01_1.VOB", "VTS_01_2.VOB"],
            "the tree survives intact - `ifo` is on no junk list and the \
             one-video arm declines on a subdirectory"
        );
    });
}
