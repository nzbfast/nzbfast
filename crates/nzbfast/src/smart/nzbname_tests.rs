//! Naming a finished job after its .nzb file (issue #32, TODO 142).
//!
//! The multi-file shapes are the point of this file. "Only the largest
//! file takes the name" is a promise about what does NOT move, so every
//! case here asserts the furniture by name after the rename, not just
//! the winner.

use super::super::testkit::*;
use super::*;

/// `name` in `dir`, `bytes` long, by `set_len` - no bytes are written.
///
/// Every size in this file is a THOUSANDTH of the release it stands
/// for: an 8 MB "feature" beside a 40 KB "sample". `main_payload` ranks
/// by length and nothing here reads an absolute size, so the ratios are
/// the whole content of a fixture and the magnitudes are decoration.
///
/// They started at the real figures, and `set_len` is only free on a
/// filesystem that hands back a hole. NTFS is not one: it reserves the
/// clusters, so the ten cases below really allocated ~15 GB, filled the
/// Windows CI runner's disk, and took out every later test in the run
/// with `ERROR_DISK_FULL` - including one in `rars` that had been green
/// for weeks. Sparseness is not portable; small is.
fn file(dir: &Path, name: &str, bytes: u64) -> PathBuf {
    let p = dir.join(name);
    let f = std::fs::File::create(&p).unwrap();
    f.set_len(bytes).unwrap();
    p
}

fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

#[test]
fn a_movie_with_samples_and_subs_renames_only_the_feature() {
    let root = scratch("nzb-movie");
    let out = root.join("Example.Movie.2024.1080p.WEB-DL-GRP");
    std::fs::create_dir_all(&out).unwrap();
    file(&out, "Example.Movie.2024.1080p.WEB-DL-GRP.mkv", 8_000_000);
    file(&out, "sample.mkv", 40_000);
    file(&out, "Example.Movie.2024.1080p.WEB-DL-GRP.en.srt", 90);
    file(&out, "example-movie.nfo", 4);
    file(&out, "Example.Movie.2024.1080p.WEB-DL-GRP.par2", 500);

    let dest = rename_from_nzb(&root, &out, "My Movie Night 2024.nzb").unwrap();
    assert_eq!(
        dest,
        root.join("My Movie Night 2024"),
        "folder takes the name"
    );
    assert_portable("My Movie Night 2024");

    // The feature, and nothing else. A sample or a subtitle wearing the
    // release identity is the on-disk version of the wall's junk-rescore
    // hazard: the library imports the wrong file.
    assert_eq!(
        names(&dest),
        vec![
            "Example.Movie.2024.1080p.WEB-DL-GRP.en.srt",
            "Example.Movie.2024.1080p.WEB-DL-GRP.par2",
            "My Movie Night 2024.mkv",
            "example-movie.nfo",
            "sample.mkv",
        ]
    );
}

#[test]
fn an_episode_pack_renames_the_largest_episode_only() {
    let root = scratch("nzb-pack");
    let out = root.join("Example.Show.S01.1080p.WEB-GRP");
    std::fs::create_dir_all(&out).unwrap();
    file(&out, "Example.Show.S01E01.1080p.WEB-GRP.mkv", 2_000_000);
    // The biggest episode is deliberately NOT the first or the last.
    file(&out, "Example.Show.S01E02.1080p.WEB-GRP.mkv", 3_000_000);
    file(&out, "Example.Show.S01E03.1080p.WEB-GRP.mkv", 2_500_000);
    file(&out, "Example.Show.S01E02.1080p.WEB-GRP.srt", 80);

    let dest = rename_from_nzb(&root, &out, "Example Show season one").unwrap();
    assert_eq!(
        names(&dest),
        vec![
            "Example Show season one.mkv",
            "Example.Show.S01E01.1080p.WEB-GRP.mkv",
            "Example.Show.S01E02.1080p.WEB-GRP.srt",
            "Example.Show.S01E03.1080p.WEB-GRP.mkv",
        ],
        "every other episode keeps its own name"
    );
}

/// The reporter's "any download": no video at all, and the payload is
/// whatever the biggest real file is.
#[test]
fn a_non_video_job_names_its_biggest_payload_file() {
    let root = scratch("nzb-other");
    let out = root.join("some.software.post");
    std::fs::create_dir_all(&out).unwrap();
    file(&out, "setup.iso", 900_000);
    file(&out, "readme.txt", 2);
    file(&out, "post.nfo", 1);

    let dest = rename_from_nzb(&root, &out, "Installer disc").unwrap();
    assert_eq!(
        names(&dest),
        vec!["Installer disc.iso", "post.nfo", "readme.txt"]
    );
}

/// A job that never unpacked: the biggest file is a RAR volume, and
/// renaming one member of a multi-volume set breaks the set.
#[test]
fn a_still_packed_set_is_never_renamed() {
    let root = scratch("nzb-packed");
    let out = root.join("blob");
    std::fs::create_dir_all(&out).unwrap();
    file(&out, "blob.part01.rar", 500_000);
    file(&out, "blob.part02.rar", 500_000);
    file(&out, "blob.nfo", 1);

    let dest = rename_from_nzb(&root, &out, "Whatever This Is").unwrap();
    assert_eq!(
        names(&dest),
        vec!["blob.nfo", "blob.part01.rar", "blob.part02.rar"],
        "the volumes keep their names; only the folder moved"
    );
}

/// The obfuscated twin of `a_still_packed_set_is_never_renamed`: a
/// numbered BYTE SPLIT of a container, where only part 1 carries the
/// head. Every per-path question `is_furniture` asks answers "ordinary
/// payload" for parts 2..=n, so the biggest of them was eligible to take
/// the release name - which breaks the set exactly the way renaming one
/// volume of a multi-volume set does, and for the same reason. The
/// directory's own membership is what settles it: see
/// `crate::container_part_set`.
#[test]
fn an_obfuscated_container_split_is_never_renamed() {
    let root = scratch("nzb-csplit");
    let out = root.join("blob");
    std::fs::create_dir_all(&out).unwrap();
    let base = "301c0186f3bbdc58ac03a8739f989391c4";
    // Part 1 opens with the container's head; the rest are the bytes
    // that follow it, and the LAST is the largest thing in the job.
    std::fs::write(out.join(format!("{base}.001")), b"Rar!\x1a\x07\x01\x00").unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(out.join(format!("{base}.001")))
        .unwrap()
        .set_len(500_000)
        .unwrap();
    file(&out, &format!("{base}.002"), 500_000);
    file(&out, &format!("{base}.003"), 400_000);
    file(&out, "blob.nfo", 1);

    let dest = rename_from_nzb(&root, &out, "Whatever This Is").unwrap();
    assert_eq!(
        names(&dest),
        vec![
            format!("{base}.001"),
            format!("{base}.002"),
            format!("{base}.003"),
            "blob.nfo".to_string(),
        ],
        "every part keeps its name; only the folder moved"
    );
}

/// The PLAIN reading of the same shape, and the more destructive of the
/// two: a numbered byte split with NO archive head on any part. The
/// container twin above at least has a part 1 that answers for itself, so
/// what it lost was the payload behind a stub it kept. Here there is
/// nothing to answer with on ANY member - carrying a head is what
/// disqualifies a set from this reading - so `is_furniture` reads every
/// part as ordinary payload and the largest one takes the release name.
/// Settled by the directory's own membership: see `crate::split_part_set`,
/// which also records how a job reaches this pass with the set unjoined.
#[test]
fn a_plain_numbered_split_is_never_renamed() {
    let root = scratch("nzb-psplit");
    let out = root.join("blob");
    std::fs::create_dir_all(&out).unwrap();
    // No head on any part, uniform sizes, gapless from 1 - and the LAST
    // part is not the largest, so the winner would be part 2.
    file(&out, "Bonus.mkv.001", 500_000);
    file(&out, "Bonus.mkv.002", 500_000);
    file(&out, "Bonus.mkv.003", 400_000);
    file(&out, "blob.nfo", 1);

    let dest = rename_from_nzb(&root, &out, "Whatever This Is").unwrap();
    assert_eq!(
        names(&dest),
        vec![
            "Bonus.mkv.001",
            "Bonus.mkv.002",
            "Bonus.mkv.003",
            "blob.nfo",
        ],
        "every part keeps its name; only the folder moved"
    );
}

/// The subfolder twin of the two split cases above, and the shape TODO
/// 301 recorded as the reachable one: the split sits one directory down.
///
/// `main_payload` reaches the top level PLUS one directory down, and it
/// used to build its three membership sets once, from the top - so a
/// part in `Extras/` was judged against the PARENT's sets, which never
/// contain it. Every set-based arm of `is_furniture` then answered
/// "ordinary payload" and the largest part took the release name:
/// observed 25 Aug 2026 as `Bonus.mkv.001` -> `Whatever This Is.001`,
/// breaking a set the user still needs. `keep_media_only` has always
/// recomputed per directory; this is that asymmetry closed.
#[test]
fn a_plain_split_in_a_subfolder_is_never_renamed() {
    let root = scratch("nzb-psplit-sub");
    let out = root.join("blob");
    let extras = out.join("Extras");
    std::fs::create_dir_all(&extras).unwrap();
    // The top-level payload is the SMALLEST thing here, so the winner
    // under the old reading was a split part one level down.
    file(&out, "Movie.mkv", 100_000);
    file(&extras, "Bonus.mkv.001", 500_000);
    file(&extras, "Bonus.mkv.002", 500_000);
    file(&extras, "Bonus.mkv.003", 400_000);

    let dest = rename_from_nzb(&root, &out, "Whatever This Is").unwrap();
    assert_eq!(
        names(&dest),
        vec!["Extras", "Whatever This Is.mkv"],
        "the top-level payload takes the name"
    );
    assert_eq!(
        names(&dest.join("Extras")),
        vec!["Bonus.mkv.001", "Bonus.mkv.002", "Bonus.mkv.003"],
        "every part keeps its name - the subfolder's own membership answers"
    );
}

/// The CONTAINER reading of the same subfolder shape. Same defect and
/// the same edit covers it: `container_part_set` has been asked of the
/// top directory since TODO 299, so a headed split one level down was
/// never in the set it was judged against.
#[test]
fn a_container_split_in_a_subfolder_is_never_renamed() {
    let root = scratch("nzb-csplit-sub");
    let out = root.join("blob");
    let extras = out.join("Extras");
    std::fs::create_dir_all(&extras).unwrap();
    file(&out, "Movie.mkv", 100_000);
    let base = "301c0186f3bbdc58ac03a8739f989391c4";
    // Part 1 opens with the container's head; the rest are the bytes
    // that follow it.
    std::fs::write(extras.join(format!("{base}.001")), b"Rar!\x1a\x07\x01\x00").unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(extras.join(format!("{base}.001")))
        .unwrap()
        .set_len(500_000)
        .unwrap();
    file(&extras, &format!("{base}.002"), 500_000);
    file(&extras, &format!("{base}.003"), 400_000);

    let dest = rename_from_nzb(&root, &out, "Whatever This Is").unwrap();
    assert_eq!(names(&dest), vec!["Extras", "Whatever This Is.mkv"]);
    assert_eq!(
        names(&dest.join("Extras")),
        vec![
            format!("{base}.001"),
            format!("{base}.002"),
            format!("{base}.003"),
        ],
        "every part keeps its name"
    );
}

/// And the ZIP arm, the third set - deliberately in the one shape only
/// `zip_part_set` can answer. A `.z01` spanned segment or a `.zip.001`
/// split part is recognised BY NAME through `nzbkit::zip::is_container`,
/// so neither needs a set at all; a BARE numeric group whose part 1
/// carries zip magic does, because parts 2..=n carry nothing in the name
/// or the head. The sizes here are uneven on purpose, which is what
/// keeps the two splitjoin readings out of it (their rule 4 wants every
/// part but the last the same size) and leaves `zip_part_set` as the
/// only thing standing between part 3 and the release name.
#[test]
fn a_bare_numeric_zip_set_in_a_subfolder_is_never_renamed() {
    let root = scratch("nzb-zipnum-sub");
    let out = root.join("blob");
    let extras = out.join("Extras");
    std::fs::create_dir_all(&extras).unwrap();
    file(&out, "Movie.mkv", 100_000);
    std::fs::write(extras.join("pack.001"), b"PK\x03\x04").unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(extras.join("pack.001"))
        .unwrap()
        .set_len(500_000)
        .unwrap();
    file(&extras, "pack.002", 300_000);
    file(&extras, "pack.003", 400_000);

    let dest = rename_from_nzb(&root, &out, "Whatever This Is").unwrap();
    assert_eq!(names(&dest), vec!["Extras", "Whatever This Is.mkv"]);
    assert_eq!(
        names(&dest.join("Extras")),
        vec!["pack.001", "pack.002", "pack.003"],
        "every part keeps its name; renaming one breaks the set"
    );
}

/// Our own state files are hidden on macOS and Linux and NOTHING on
/// Windows. A failed job keeps its journal so a retry fetches only what
/// is missing, so "it will not be there" is not a defence either.
#[test]
fn our_own_dotfiles_are_never_the_main_file() {
    let root = scratch("nzb-dot");
    let out = root.join("job");
    std::fs::create_dir_all(&out).unwrap();
    file(&out, ".nzbfast.journal", 900_000);
    file(&out, "payload.mkv", 100_000);

    let dest = rename_from_nzb(&root, &out, "Chosen Name").unwrap();
    assert_eq!(names(&dest), vec![".nzbfast.journal", "Chosen Name.mkv"]);
}

#[test]
fn a_folder_already_named_after_the_nzb_is_left_alone() {
    let root = scratch("nzb-noop");
    // Exactly what `enqueue` builds: the same sanitiser on the same
    // string. The common case is that only the file needs renaming.
    let out = root.join("Chosen Name");
    std::fs::create_dir_all(&out).unwrap();
    file(&out, "hash1fRbH6e0eX8v.mkv", 100_000);
    assert_eq!(rename_from_nzb(&root, &out, "Chosen Name.nzb"), None);
    assert_eq!(names(&out), vec!["Chosen Name.mkv"]);

    // A collision suffix is load-bearing - the unsuffixed name is
    // another job's payload - so it is not "tidied" back onto it.
    let out2 = root.join("Chosen Name.2");
    std::fs::create_dir_all(&out2).unwrap();
    file(&out2, "hash9zQ.mkv", 100_000);
    assert_eq!(rename_from_nzb(&root, &out2, "Chosen Name"), None);
    assert!(out.is_dir() && out2.is_dir());
}

#[test]
fn the_name_is_sanitised_the_way_the_job_folder_was() {
    let root = scratch("nzb-sanitize");
    let out = root.join("job");
    std::fs::create_dir_all(&out).unwrap();
    file(&out, "payload.mkv", 10);
    // Path separators and control characters cannot reach the
    // filesystem; a name that survives that is used AS WRITTEN, dots
    // and all - tidying it up is what this option exists to stop.
    let dest = rename_from_nzb(&root, &out, "sub/dir\u{7}Name.2024.1080p").unwrap();
    let leaf = dest.file_name().unwrap().to_string_lossy().into_owned();
    assert_eq!(leaf, "sub_dir_Name.2024.1080p");
    assert_portable(&leaf);
    assert_eq!(names(&dest), vec!["sub_dir_Name.2024.1080p.mkv"]);
}

#[test]
fn a_name_with_nothing_usable_left_renames_nothing() {
    let root = scratch("nzb-empty");
    let out = root.join("job");
    std::fs::create_dir_all(&out).unwrap();
    file(&out, "payload.mkv", 10);
    assert_eq!(rename_from_nzb(&root, &out, "  ...  "), None);
    assert_eq!(names(&out), vec!["payload.mkv"]);
}

/// An existing file already holds the target name. Leaving the main
/// file alone is the cheap outcome; overwriting a payload is not.
#[test]
fn a_taken_filename_is_not_overwritten() {
    let root = scratch("nzb-taken");
    let out = root.join("job");
    std::fs::create_dir_all(&out).unwrap();
    file(&out, "big.mkv", 100);
    file(&out, "Taken.mkv", 50);
    let dest = rename_from_nzb(&root, &out, "Taken").unwrap();
    assert_eq!(names(&dest), vec!["Taken.mkv", "big.mkv"]);
    assert_eq!(
        std::fs::metadata(dest.join("Taken.mkv")).unwrap().len(),
        50,
        "the file that was already there is untouched"
    );
}

#[test]
fn an_extracted_subdirectory_is_reached_and_the_folder_still_moves() {
    let root = scratch("nzb-sub");
    let out = root.join("job");
    let inner = out.join("Example.Movie.2024");
    std::fs::create_dir_all(&inner).unwrap();
    file(&inner, "Example.Movie.2024.mkv", 4_000_000);
    file(&out, "job.nfo", 1);

    let dest = rename_from_nzb(&root, &out, "Movie Night").unwrap();
    assert_eq!(names(&dest), vec!["Example.Movie.2024", "job.nfo"]);
    assert_eq!(
        names(&dest.join("Example.Movie.2024")),
        vec!["Movie Night.mkv"],
        "renamed in place, one level down"
    );
}
