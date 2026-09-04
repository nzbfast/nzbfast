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

/// The same promise as `a_taken_filename_is_not_overwritten` above,
/// held to an ENTRY rather than to a name that RESOLVES. This site is
/// what the 31 Aug 2026 census meant by "treat 12 as a floor": its guard
/// sits twelve lines from its rename, so the proximity scan that found
/// the other twelve never saw it, and `Path::exists` followed the link
/// and reported free while `rename(2)` removed the entry.
#[test]
fn a_filename_an_entry_holds_is_not_overwritten() {
    let root = scratch("nzb-taken-link");
    let out = root.join("job");
    std::fs::create_dir_all(&out).unwrap();
    file(&out, "big.mkv", 100);

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(out.join("on-the-nas"), out.join("Taken.mkv")).unwrap();
        let dest = rename_from_nzb(&root, &out, "Taken").unwrap();
        assert_eq!(names(&dest), vec!["Taken.mkv", "big.mkv"]);
        assert!(
            std::fs::symlink_metadata(dest.join("Taken.mkv"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "a dangling link is an entry: the user's link must still be a link"
        );
        assert_eq!(
            std::fs::metadata(dest.join("big.mkv")).unwrap().len(),
            100,
            "and the payload keeps the name it arrived with"
        );
    }
    // PORTABLE half: the folder still moves and the main file is still
    // the only thing that could have been renamed, so the windows-unit
    // shards run this door even where the link half cannot be built.
    #[cfg(not(unix))]
    {
        let dest = rename_from_nzb(&root, &out, "Taken").unwrap();
        assert_eq!(names(&dest), vec!["Taken.mkv"]);
    }
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

/// Every path in a subtree of `dir`, relative and sorted - the whole
/// tree rather than one level, because "the disc is intact" is a claim
/// about every name in it and a one-level `names()` cannot make it.
fn tree(dir: &Path) -> Vec<String> {
    let mut v = Vec::new();
    let mut queue = vec![dir.to_path_buf()];
    while let Some(at) = queue.pop() {
        for e in std::fs::read_dir(&at).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                queue.push(p.clone());
            }
            // FORWARD SLASHES, always. `to_string_lossy` on a relative
            // path gives the platform's own separator, so every
            // expectation below - which spells a disc tree the way the
            // spec and the poster do, `VIDEO_TS/VTS_01_1.VOB` - failed
            // on Windows and nowhere else. It took windows-unit shards
            // 3 and 5 red on 31 Aug 2026 with the product behaving
            // perfectly: the disc rows are about which NAMES survive a
            // rename, and a separator is not a name.
            //
            // Normalised BEFORE the sort, which is the half that is easy
            // to miss: `\` is 0x5C and `/` is 0x2F, so sorting raw
            // strings orders a nested path differently on the two
            // platforms even once the comparison is fixed.
            v.push(
                p.strip_prefix(dir)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
    v.sort();
    v
}

/// The Blu-ray half of the disc arm, measured FAILING on origin/main:
/// the deepest thing `main_payload` could see was `BDMV/index.bdmv` -
/// the file a player opens FIRST - so it took the release name and the
/// disc stopped playing over a Completed job.
///
/// The folder still moves. That is the whole design: a disc rip's
/// identity belongs to the FOLDER, which is the one name in the tree
/// nothing inside it addresses.
#[test]
fn a_blu_ray_tree_keeps_every_name_and_only_the_folder_moves() {
    let root = scratch("nzb-bdmv");
    let out = root.join("job");
    std::fs::create_dir_all(out.join("BDMV/STREAM")).unwrap();
    std::fs::create_dir_all(out.join("CERTIFICATE")).unwrap();
    file(&out.join("BDMV/STREAM"), "00000.m2ts", 40_000);
    file(&out.join("BDMV"), "index.bdmv", 900);
    file(&out.join("BDMV"), "MovieObject.bdmv", 500);
    file(&out.join("CERTIFICATE"), "id.bdmv", 100);

    assert_eq!(
        main_payload(&out),
        None,
        "a disc has no main file whose name is free to change"
    );
    let dest = rename_from_nzb(&root, &out, "Great.Movie.2024.BluRay").unwrap();
    assert_eq!(dest, root.join("Great.Movie.2024.BluRay"));
    assert_eq!(
        tree(&dest),
        vec![
            "BDMV",
            "BDMV/MovieObject.bdmv",
            "BDMV/STREAM",
            "BDMV/STREAM/00000.m2ts",
            "BDMV/index.bdmv",
            "CERTIFICATE",
            "CERTIFICATE/id.bdmv",
        ],
        "index.bdmv is what a player opens first and must keep its name"
    );
}

/// The DVD-Video half, and the worse one: `VIDEO_TS/VTS_01_1.VOB` sits
/// at exactly root + one, so the old reach did not merely graze a
/// structure file, it renamed the WHOLE PAYLOAD - measured on
/// origin/main as `VIDEO_TS/Great.Movie.2024.DVD.vob`, lowercasing the
/// extension on the way, while `VIDEO_TS.IFO` went on addressing it by
/// its old name.
///
/// Not in the report that led here; found by driving the same fixture
/// shape one disc format over.
#[test]
fn a_dvd_video_tree_keeps_its_vob_name() {
    let root = scratch("nzb-dvd");
    let out = root.join("job");
    std::fs::create_dir_all(out.join("VIDEO_TS")).unwrap();
    file(&out.join("VIDEO_TS"), "VTS_01_1.VOB", 40_000);
    file(&out.join("VIDEO_TS"), "VIDEO_TS.IFO", 900);
    file(&out.join("VIDEO_TS"), "VIDEO_TS.BUP", 900);

    assert_eq!(main_payload(&out), None);
    let dest = rename_from_nzb(&root, &out, "Great.Movie.2024.DVD").unwrap();
    assert_eq!(
        tree(&dest),
        vec![
            "VIDEO_TS",
            "VIDEO_TS/VIDEO_TS.BUP",
            "VIDEO_TS/VIDEO_TS.IFO",
            "VIDEO_TS/VTS_01_1.VOB",
        ],
        "VIDEO_TS.IFO addresses VTS_01_1.VOB by name"
    );
}

/// A disc wrapped in a release folder, which is the shape most posters
/// actually use, and an AVCHD card layout four deep. Neither has a
/// single reachable file at all under the old reach, so both were
/// already safe by accident - pinned so that widening the reach later
/// cannot quietly make them unsafe, which is the change the doc comment
/// on `main_payload` forbids in words.
#[test]
fn a_wrapped_disc_and_an_avchd_card_are_both_declined() {
    let root = scratch("nzb-wrapped");
    let out = root.join("job");
    let bd = out.join("Movie.2024.COMPLETE.BLURAY/BDMV/STREAM");
    std::fs::create_dir_all(&bd).unwrap();
    file(&bd, "00000.m2ts", 40_000);
    file(&out.join("Movie.2024.COMPLETE.BLURAY"), "readme.nfo", 10);
    assert_eq!(main_payload(&out), None);
    drop(root);

    let root = scratch("nzb-avchd");
    let out = root.join("job");
    let mts = out.join("PRIVATE/AVCHD/BDMV/STREAM");
    std::fs::create_dir_all(&mts).unwrap();
    file(&mts, "00000.MTS", 9_000);
    assert_eq!(main_payload(&out), None);
}

/// A disc posted FLAT, with no structure directory to match on. It is
/// already not playable as it stands, and it is exactly the shape a
/// user re-trees by hand - so the numbers `.mpls` and `.clpi` address
/// the stream by must survive. The `.bdmv` file is what says "disc"
/// here; there is no directory to say it.
#[test]
fn a_flattened_disc_post_is_declined_on_its_structure_files() {
    let root = scratch("nzb-flatdisc");
    let out = root.join("job");
    std::fs::create_dir_all(&out).unwrap();
    file(&out, "00000.m2ts", 40_000);
    file(&out, "index.bdmv", 900);
    file(&out, "00000.mpls", 300);

    assert_eq!(main_payload(&out), None);
    let dest = rename_from_nzb(&root, &out, "Great.Movie.2024").unwrap();
    assert_eq!(
        names(&dest),
        vec!["00000.m2ts", "00000.mpls", "index.bdmv"],
        "a stream file is addressed by NUMBER, so its number is its name"
    );
}

/// The other direction, and the one that keeps the disc arm from being
/// a licence to decline: an ordinary release still renames exactly one
/// file, and a `.sup` subtitle or an external `.eac3` track beside it -
/// both of which are in `MEDIA_COMPANION_EXTS` and neither of which is
/// disc structure - does not make the job look like a disc.
#[test]
fn a_release_with_companion_tracks_is_not_a_disc() {
    let root = scratch("nzb-companions");
    let out = root.join("job");
    std::fs::create_dir_all(&out).unwrap();
    file(&out, "Example.Movie.2024.mkv", 8_000_000);
    file(&out, "Example.Movie.2024.sup", 40_000);
    file(&out, "Example.Movie.2024.eac3", 90_000);

    let dest = rename_from_nzb(&root, &out, "Movie Night").unwrap();
    assert_eq!(
        names(&dest),
        vec![
            "Example.Movie.2024.eac3",
            "Example.Movie.2024.sup",
            "Movie Night.mkv",
        ]
    );
}

/// A cue sheet is a NAME MAP, so both halves of the pair are refused.
/// The data half is the failure this test was written for: it is the
/// biggest thing in a CD rip, so it took the release name and left the
/// sheet addressing a file that was no longer there - the M4-88 shape
/// reached through the naming door. The sheet is refused for its own
/// reason, measured after the first half was fixed: see the multi-disc
/// case below.
#[test]
fn a_cue_rip_renames_the_folder_and_nothing_the_sheet_addresses() {
    let root = scratch("nzb-cue-pair");
    let out = root.join("Some.Album.2024.FLAC-GRP");
    std::fs::create_dir_all(&out).unwrap();
    file(&out, "Album.bin", 40_000);
    std::fs::write(
        out.join("Album.cue"),
        b"REM GENRE Rock\nFILE \"Album.bin\" BINARY\n  TRACK 01 AUDIO\n",
    )
    .unwrap();
    // Unrelated furniture, to prove the pair is not simply the only
    // thing here: the job still declines to name a file.
    file(&out, "album.nfo", 4);

    let dest = rename_from_nzb(&root, &out, "My Album 2024.nzb").unwrap();
    assert_eq!(
        dest,
        root.join("My Album 2024"),
        "the folder takes the name"
    );
    assert_eq!(
        names(&dest),
        vec!["Album.bin", "Album.cue", "album.nfo"],
        "the sheet goes on addressing the file it names"
    );
}

/// The sheet half, and why it is refused rather than left eligible.
/// Sparing only the data makes a SHEET the biggest thing left, and this
/// shape came back as `CD1.bin`, `CD1.cue`, `CD2.bin`,
/// `My Album 2024.cue` - nothing dangling, and no way left to tell which
/// sheet is disc 2.
#[test]
fn a_two_disc_rip_keeps_both_sheets_numbered() {
    let root = scratch("nzb-cue-multi");
    let out = root.join("Some.Album.2024.FLAC-GRP");
    std::fs::create_dir_all(&out).unwrap();
    for disc in ["CD1", "CD2"] {
        file(&out, &format!("{disc}.bin"), 40_000);
        std::fs::write(
            out.join(format!("{disc}.cue")),
            format!("FILE \"{disc}.bin\" BINARY\n").as_bytes(),
        )
        .unwrap();
    }

    let dest = rename_from_nzb(&root, &out, "My Album 2024.nzb").unwrap();
    assert_eq!(
        names(&dest),
        vec!["CD1.bin", "CD1.cue", "CD2.bin", "CD2.cue"],
        "every name in a cue set is load-bearing, the numbering included"
    );
}

/// The narrow rule, not the disc-tree one: an ordinary release that
/// happens to ship a cue set beside the feature still gets its rename.
/// `feature::disc_structure` declines a whole JOB and is right to for a
/// DVD or Blu-ray tree; a loose CD rip beside a film is not one.
#[test]
fn a_feature_beside_a_cue_set_is_still_named() {
    let root = scratch("nzb-cue-mixed");
    let out = root.join("Example.Movie.2024.1080p-GRP");
    std::fs::create_dir_all(&out).unwrap();
    file(&out, "Example.Movie.2024.1080p-GRP.mkv", 8_000_000);
    file(&out, "Soundtrack.bin", 40_000);
    std::fs::write(
        out.join("Soundtrack.cue"),
        b"FILE \"Soundtrack.bin\" BINARY\n",
    )
    .unwrap();

    let dest = rename_from_nzb(&root, &out, "My Movie Night 2024.nzb").unwrap();
    assert_eq!(
        names(&dest),
        vec![
            "My Movie Night 2024.mkv",
            "Soundtrack.bin",
            "Soundtrack.cue"
        ],
        "the feature takes the name and the cue set keeps both of its own"
    );
}

/// Membership is a property of the DIRECTORY, so a cue set one level
/// down is answered by ITS OWN sheet - the asymmetry TODO 301 records
/// for the split-part sets, on the arm added after it.
#[test]
fn a_cue_set_in_a_subfolder_is_read_against_its_own_directory() {
    let root = scratch("nzb-cue-sub");
    let out = root.join("Some.Release.2024-GRP");
    let extras = out.join("Extras");
    std::fs::create_dir_all(&extras).unwrap();
    file(&out, "Some.Release.2024-GRP.nfo", 4);
    file(&extras, "Bonus.bin", 40_000);
    std::fs::write(extras.join("Bonus.cue"), b"FILE \"Bonus.bin\" BINARY\n").unwrap();

    let dest = rename_from_nzb(&root, &out, "My Release 2024.nzb").unwrap();
    assert_eq!(
        names(&dest.join("Extras")),
        vec!["Bonus.bin", "Bonus.cue"],
        "the parent's empty cue set must not read a subfolder's pair as payload"
    );
}

/// The main file's occupancy guard is a CLAIM, so a name that arrives
/// while `rename_from_nzb` is running cannot be renamed over.
///
/// The `symlink_metadata` this door carried until 31 Aug 2026 answers
/// the occupancy question exactly as the `create_new` claim does; what
/// separates them is the gap behind the answer, so this has to race.
/// See `crate::renameclaim` for the measurement. VERIFIED red with
/// `rename_main_file` alone reverted to the `lstat`.
///
/// Driven through `rename_from_nzb` because `rename_main_file` is
/// private to `nzbname`. The job folder is ALREADY named after the
/// base, so `rename_dir` sees `want == out_dir` and returns None -
/// which is what keeps the directory still under the harness while the
/// trials run, and it leaves the folder ladder (a DIRECTORY source,
/// which `rename(2)` refuses onto any existing entry) correctly out of
/// this claim's scope. THAT EXCLUSION IS ABOUT THE RENAME AND NOT ABOUT
/// THE FOLDER: `rename(2)` refusing is only the ladder's first attempt,
/// and the fallback behind it merged - see
/// `the_entry_by_entry_fallback_refuses_to_merge_into_a_neighbour`
/// below, which is where the folder half is pinned.
#[test]
fn a_main_file_name_created_beside_the_rename_is_never_renamed_over() {
    let root = scratch("nzb-claim-race");
    let base = "My Movie Night 2024";
    let out = root.join(base);
    std::fs::create_dir_all(&out).unwrap();
    let target = out.join(format!("{base}.mkv"));
    crate::renameclaim::never_renames_over_a_neighbour(
        &target,
        300,
        || {
            file(&out, "Example.Movie.2024.1080p.WEB-DL-GRP.mkv", 8_000_000);
        },
        || {
            rename_from_nzb(&root, &out, base);
        },
    );
}

/// The entry-by-entry fallback REFUSES a directory it did not create,
/// and moves nothing when it does.
///
/// This is the destructive step, and it is worth stating plainly why
/// this pin does not have to race where its neighbour above does. The
/// claim-versus-look pins race because both answers agree on every
/// question a single thread can ask. These two do not: `create_dir_all`
/// answers Ok for an existing directory and `create_dir` answers
/// `AlreadyExists`, with no second thread anywhere. So the exact pin is
/// the cheap one.
///
/// What the old spelling did, and what this asserts against: the
/// per-entry `rename` REPLACES a same-named file, so a fallback that
/// merged put the loser's `payload.mkv` over the winner's and deleted
/// the loser's folder - both jobs then logging a successful rename with
/// one job's payload gone. VERIFIED red with `create_dir` reverted to
/// `create_dir_all`: the neighbour's 4,096 bytes come back 1,000.
#[test]
fn the_entry_by_entry_fallback_refuses_to_merge_into_a_neighbour() {
    let root = scratch("nzb-fallback-merge");
    let neighbour = root.join("Example Movie 2019");
    std::fs::create_dir_all(&neighbour).unwrap();
    file(&neighbour, "payload.mkv", 4_096);
    file(&neighbour, "theirs.nfo", 40);

    let mine = root.join("job-abc123");
    std::fs::create_dir_all(&mine).unwrap();
    file(&mine, "payload.mkv", 1_000);
    file(&mine, "mine.nfo", 10);

    let e = move_dir_contents(&mine, &neighbour).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists, "{e}");

    // Nothing moved, in either direction: the neighbour keeps its own
    // bytes under the contested name, and this job still holds all of
    // its own entries under its own folder.
    assert_eq!(
        std::fs::metadata(neighbour.join("payload.mkv"))
            .unwrap()
            .len(),
        4_096
    );
    assert_eq!(names(&neighbour), ["payload.mkv", "theirs.nfo"]);
    assert_eq!(names(&mine), ["mine.nfo", "payload.mkv"]);
}

/// And the ladder STEPS on that refusal rather than reporting a failed
/// rename: the loser lands on `base.2`, which is what the ladder is for.
///
/// Deterministic because the refusal is, and it drives `rename_dir`
/// itself so the retry loop is what is being read - the fallback is
/// reached here the way Windows reaches it, by a rename that fails with
/// the name already taken. On Unix that is ENOTEMPTY from the
/// neighbour's own payload.
#[test]
fn the_folder_ladder_steps_past_a_neighbour_it_cannot_merge_into() {
    let root = scratch("nzb-ladder-step");
    let base = "Example Movie 2019";
    let neighbour = root.join(base);
    std::fs::create_dir_all(&neighbour).unwrap();
    file(&neighbour, "payload.mkv", 4_096);

    let mine = root.join("job-abc123");
    std::fs::create_dir_all(&mine).unwrap();
    file(&mine, "payload.mkv", 1_000);

    let landed = rename_dir(&root, &mine, base).expect("the folder moves");
    assert_eq!(landed, root.join("Example Movie 2019.2"));
    assert_eq!(
        std::fs::metadata(neighbour.join("payload.mkv"))
            .unwrap()
            .len(),
        4_096
    );
    assert_eq!(
        std::fs::metadata(landed.join("payload.mkv")).unwrap().len(),
        1_000
    );
}

/// End to end, against a folder that ARRIVES in the gap - the shape the
/// ladder cannot see, since it skips every entry that is there when it
/// looks.
///
/// RACES, and it is the only one of these three that has to. The two
/// pins above read the refusal, which is deterministic; this one reads
/// what the whole door does when the name is taken between the look and
/// the rename, and there is no way to reach that state without a second
/// thread - the ladder skips every entry it can see.
///
/// The classification is exact and needs no timing. The adversary's
/// folder is built ONCE, away from the ladder's parent, and moved into
/// place by a single `rename`: a directory that appears with its payload
/// already inside. So its return value says whether it held the name
/// with 4,096 bytes under it, atomically - built empty and filled
/// afterwards it would be renameable-onto while it stayed empty, and
/// this would be reading that instead.
///
/// THE ARRIVAL HILL-CLIMBS, for the reason `renameclaim`'s header gives
/// at length, and both halves of that argument were needed here.
/// MEASURED on the dev Mac, arrivals that held the name, of 300 trials:
/// a thread SPAWNED per trial reaches the window 2 times, because the
/// door is a handful of syscalls and is over before a fresh thread
/// runs; one PERSISTENT adversary released by the same flag as the
/// door reaches it 3 to 11 times, because the door still gets to the
/// parent directory first even with the offset pinned at its zero
/// floor; a persistent adversary plus the `LEAD` below, which starts
/// the door late enough to be reachable, settles at 149-150 of 300,
/// which is the climb straddling the rename one step either side.
///
/// VERIFIED red with `create_dir` reverted to `create_dir_all`: 149,
/// 150 and 149 of those arrivals were merged over, across three runs.
/// Half of every contended pair loses its payload, so this is not a
/// narrow window - it is what the door did whenever it was raced.
#[test]
fn a_folder_that_arrives_on_the_name_is_never_merged_into() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    let root = scratch("nzb-folder-race");
    let base = "Example Movie 2019";
    let target = root.join(base);
    let staging = root.join("staging");
    let trials = 300;

    let go = Arc::new(AtomicBool::new(false));
    let armed = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let held = Arc::new(AtomicBool::new(false));
    // THE DOOR STARTS LATE, by `LEAD`, which is the other half of the
    // same argument: released the instant the adversary arms, the door
    // still won 289-297 of 300 with the offset pinned at its zero floor
    // - it issues one more syscall than the adversary and still gets
    // to the parent directory first, so there was nothing left to steer
    // with. Waiting `LEAD` puts the door's rename in the MIDDLE of the
    // arrival's reachable range, and the climb starts centred on it.
    const LEAD: u64 = 20_000;
    let offset = Arc::new(AtomicU64::new(LEAD));

    let (s, t, g, a, st, h, off) = (
        staging.clone(),
        target.clone(),
        go.clone(),
        armed.clone(),
        stop.clone(),
        held.clone(),
        offset.clone(),
    );
    let adversary = std::thread::spawn(move || {
        loop {
            while !g.load(Ordering::Acquire) {
                if st.load(Ordering::Relaxed) {
                    return;
                }
                std::hint::spin_loop();
            }
            // The clock starts HERE, on this thread, and `armed` then
            // releases the door - so everything a descheduled spinner
            // pays between the flag and this line is absorbed instead of
            // counted against the offset, and the door's start sits
            // inside the arrival's reachable range rather than at its
            // edge. Released by one flag, the earliest an arrival could
            // land was the door's own start, and MEASURED here that put
            // the adversary behind the door on nearly every trial: 0, 4
            // and 10 wins of 300 across three runs, so the floor below
            // fires on a green tree about a third of the time.
            let at = std::time::Instant::now();
            let wait = off.load(Ordering::Relaxed);
            a.store(true, Ordering::Release);
            while (at.elapsed().as_nanos() as u64) < wait {
                std::hint::spin_loop();
            }
            h.store(std::fs::rename(&s, &t).is_ok(), Ordering::Release);
            g.store(false, Ordering::Release);
        }
    });

    let mut wins = 0usize;
    let mut merged = 0usize;
    for _ in 0..trials {
        let _ = std::fs::remove_dir_all(&target);
        let _ = std::fs::remove_dir_all(root.join(format!("{base}.2")));
        std::fs::create_dir_all(&staging).unwrap();
        file(&staging, "payload.mkv", 4_096);
        let mine = root.join("job-abc123");
        std::fs::create_dir_all(&mine).unwrap();
        file(&mine, "payload.mkv", 1_000);

        armed.store(false, Ordering::Release);
        go.store(true, Ordering::Release);
        while !armed.load(Ordering::Acquire) {
            std::hint::spin_loop();
        }
        let start = std::time::Instant::now();
        while (start.elapsed().as_nanos() as u64) < LEAD {
            std::hint::spin_loop();
        }
        rename_dir(&root, &mine, base);
        while go.load(Ordering::Acquire) {
            std::hint::spin_loop();
        }

        let step = 2_000;
        if held.load(Ordering::Acquire) {
            wins += 1;
            offset.fetch_add(step, Ordering::Relaxed);
            if std::fs::metadata(target.join("payload.mkv")).unwrap().len() != 4_096 {
                merged += 1;
            }
        } else {
            offset
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |o| {
                    Some(o.saturating_sub(step))
                })
                .ok();
        }
        let _ = std::fs::remove_dir_all(&mine);
    }
    stop.store(true, Ordering::Relaxed);
    adversary.join().unwrap();

    assert_eq!(merged, 0, "{merged} of {wins} arrivals were merged over");
    // FLOORED: an adversary that never got the name would make every
    // trial vacuous and this green having raced nothing. Low, because a
    // loaded CI box decides where an arrival lands, not the climb.
    assert!(wins > 0, "raced nothing: no arrival ever held the name");
}
