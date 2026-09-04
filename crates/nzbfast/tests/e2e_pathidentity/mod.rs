//! Path-identity regression pins: the checked path and the opened one
//! must be the same thing (X5-06, X5-08, X5-19).
//!
//! Provenance: these four were written as verification fixtures on a
//! branch, where they were RED against the tree at the time - which is
//! what confirmed the three rows before any fix existed. They land here
//! unchanged, as the pins for
//! `nzbkit::disk::relpath::open_out_leaf`. Each asserts the CORRECT
//! behaviour, so each was a demonstration of the defect first and is a
//! regression pin second; do not "simplify" one into asserting what the
//! code currently does.
//!
//! They were not landed with their siblings: that branch's module
//! carries every row of the same review, most of them still red, so
//! landing it whole would have reddened main.
//!
//! They are the SURFACE half. The mechanism has its own unit tests next
//! to it in `crates/nzbkit-base/src/disk/relpath.rs`, which is where the
//! ancestor-symlink hold-out and the three open modes are pinned; these
//! four assert the same three refusals through the constructors the
//! download and extraction paths actually call, because the defect was
//! that those constructors re-opened by NAME what
//! `prepare_out_path` had checked.
//!
//! The module is named for the CONCERN rather than for the review that
//! found it: four lanes off that review were landing in parallel, and
//! one shared file would have had them union-merging each other's
//! still-red probes.

use super::*;
use std::io::Write as _;

/// Bytes a sentinel starts with. Any change to the file is the failure,
/// so the content only has to be recognisable.
const SENTINEL: &[u8] = b"SENTINEL - nothing in the job may touch this inode\n";

/// A scratch root with `out/` (the job's output dir) and `outside/`
/// (everything the job must never reach) already made.
fn pathid_dirs(tag: &str) -> (scratch::ScratchDir, PathBuf, PathBuf) {
    let base = std::env::temp_dir().join(format!("nzbfast-pathid-{tag}-{}", std::process::id()));
    let guard = scratch::ScratchDir::attach(&base);
    let out = base.join("out");
    let outside = base.join("outside");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    (guard, out, outside)
}

/// Write a sentinel file and hand back its path. Only the alias arms
/// plant one, and those are unix-only (Windows has no unprivileged way
/// to create the symlink they turn on), so this is too - an ungated
/// helper is `dead_code` on the Windows build, which `-D warnings`
/// refuses.
#[cfg(unix)]
fn plant_sentinel(dir: &Path, name: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, SENTINEL).unwrap();
    p
}

// ---------------------------------------------------------------- X5-06

/// X5-06 (fresh-write arm): a symlink planted at the payload leaf must
/// not redirect downloader writes. `create_out_dirs` validates every
/// PARENT component and refuses a symlink there, but the LEAF is never
/// checked - `FileWriter::create_capped` opens it with `truncate(true)`
/// and follows it.
#[cfg(unix)]
#[test]
fn x5_06_a_planted_leaf_alias_must_not_redirect_a_fresh_write() {
    let (_g, out, outside) = pathid_dirs("x506new");
    let sentinel = plant_sentinel(&outside, "sentinel.bin");
    let leaf = out.join("payload.bin");
    std::os::unix::fs::symlink(&sentinel, &leaf).unwrap();

    let target = nzbkit::disk::prepare_out_path(&out, "payload.bin").unwrap();
    let w = nzbkit::disk::FileWriter::create_capped(&target, 64, 1 << 20);
    drop(w);

    assert_eq!(
        std::fs::read(&sentinel).unwrap_or_default(),
        SENTINEL,
        "the fresh-write open followed a planted leaf symlink and \
         truncated an outside inode"
    );
}

/// X5-06 (resume arm): the non-truncating resume open follows the same
/// alias and can still resize the outside inode through it.
#[cfg(unix)]
#[test]
fn x5_06_a_planted_leaf_alias_must_not_redirect_a_resume_write() {
    let (_g, out, outside) = pathid_dirs("x506res");
    let sentinel = plant_sentinel(&outside, "sentinel.bin");
    let before = std::fs::metadata(&sentinel).unwrap().len();
    let leaf = out.join("payload.bin");
    std::os::unix::fs::symlink(&sentinel, &leaf).unwrap();

    let target = nzbkit::disk::prepare_out_path(&out, "payload.bin").unwrap();
    let w = nzbkit::disk::FileWriter::create_resume_capped(&target, 4096, 1 << 20);
    drop(w);

    let after = std::fs::metadata(&sentinel).unwrap().len();
    assert_eq!(
        after, before,
        "the resume open followed a planted leaf symlink and resized an \
         outside inode ({before} -> {after} bytes)"
    );
}

// ---------------------------------------------------------------- X5-08

/// X5-08: the parent `prepare_out_path` checked must be the parent
/// actually used. Validation and the later open are two path-based
/// operations, so a directory swapped for a symlink between them sends
/// the write outside - the containment TOCTOU the row names.
#[cfg(unix)]
#[test]
fn x5_08_a_checked_parent_must_remain_the_parent_used() {
    let (_g, out, outside) = pathid_dirs("x508toctou");
    let elsewhere = outside.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();

    // Check: `safe/` is created and validated as a real directory.
    let target = nzbkit::disk::prepare_out_path(&out, "safe/payload.bin").unwrap();

    // The swap the row asks for, between check and use.
    let safe = out.join("safe");
    std::fs::remove_dir(&safe).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &safe).unwrap();

    // Use: the write site opens the path it was handed.
    let w = nzbkit::disk::FileWriter::create_capped(&target, 16, 1 << 20);
    drop(w);

    let escaped = elsewhere.join("payload.bin");
    assert!(
        !escaped.exists(),
        "the write followed a parent swapped after validation and \
         created {} outside the output directory",
        escaped.display()
    );
}

// ----------------------------------------------- the root that is a link

/// The COST of the refusal above, closed: `--out` pointed at a symlink
/// must still download. `open_out_leaf` refuses a payload whose
/// immediate parent is a symlink, and for a flat name that parent IS
/// the output directory - so a user whose downloads folder is a link to
/// another volume got a loud error on the first write where they used
/// to get a file. `get_with_progress` resolves the root once at job
/// start (`nzbkit::disk::resolve_out_root`); this is the surface half
/// of that, driving a real job through the CLI.
///
/// It is deliberately a WHOLE JOB and not a unit call: the unit tests
/// beside `resolve_out_root` pin the resolution, and what this adds is
/// that the resolved root is the one the download, the journal and the
/// settle pass all actually use - one of them left on the link spelling
/// is what a unit test cannot see.
///
/// Unix-only for the reason `plant_sentinel` is: Windows has no
/// unprivileged way to create the link. The Windows half of the same
/// hazard is a JUNCTION, which `resolve_out_root` covers through the
/// same `is_symlink` test, and which no box on this fleet can make.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_symlinked_output_root_still_downloads() {
    let mut fx = Fixture::new("pathidlinkroot");
    let data = payload(300_000, 77);
    fx.add_file("movie.mkv", &data, 60_000);
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();

    // The shape the regression broke: --out names a symlink to the real
    // output directory.
    let real = fx.dir.join("real-out");
    std::fs::create_dir_all(&real).unwrap();
    let link = fx.dir.join("linked-out");
    std::os::unix::fs::symlink(&real, &link).unwrap();

    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, link) = (cfg.clone(), nzb.clone(), link.clone());
        move || run_get(&cfg, &nzb, &link, &[])
    })
    .await
    .unwrap();
    assert!(ok, "get failed with a symlinked --out:\n{log}");
    // Through the link and at the real directory: the same inode either
    // way, so both spellings are asserted rather than one.
    assert_eq!(
        std::fs::read(link.join("movie.mkv")).unwrap_or_default(),
        data,
        "the payload did not land under the symlinked output root\n{log}"
    );
    assert_eq!(
        std::fs::read(real.join("movie.mkv")).unwrap_or_default(),
        data,
        "the payload did not land in the directory the link names\n{log}"
    );
    // The link is still a link - resolving the root must not have
    // replaced the user's own directory entry with a real directory.
    assert!(
        std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink(),
        "the output root stopped being a symlink\n{log}"
    );
}

// ------------------------------------------------- the ancestor swap

/// Plant `out/a/b/` and then swap `a` for a link to `elsewhere/`,
/// leaving `out/a/b/leaf` naming a directory outside the job. Hands
/// back the escape path the write must never reach.
#[cfg(unix)]
fn swap_the_ancestor(out: &Path, outside: &Path, leaf: &str) -> PathBuf {
    let elsewhere = outside.join("elsewhere");
    std::fs::create_dir_all(elsewhere.join("b")).unwrap();
    nzbkit::disk::prepare_out_path(out, &format!("a/b/{leaf}")).unwrap();
    std::fs::remove_dir(out.join("a").join("b")).unwrap();
    std::fs::remove_dir(out.join("a")).unwrap();
    std::os::unix::fs::symlink(&elsewhere, out.join("a")).unwrap();
    elsewhere.join("b").join(leaf)
}

/// X5-06/08/19 RESIDUE 2: a swap ABOVE the immediate parent. The landed
/// fix binds the leaf and its immediate parent, so `out/a/b/leaf.bin`
/// with `a` swapped is still followed - an output name may carry up to
/// `MAX_DEPTH` components, and a Blu-ray tree
/// (`BDMV/STREAM/00001.m2ts`) is exactly that shape.
///
/// WHAT THIS PROVES AND WHAT IT DOES NOT, because the difference is the
/// whole reason both doors exist. It proves the PATH door resolves
/// `out/a/b` in one step and follows the link, and that the
/// root-anchored door does not - which is why the escape is asserted to
/// happen first rather than assumed. It does NOT prove the racing case:
/// closing the window between the directories being validated and the
/// payload being opened is what `open_out_leaf_under` adds over
/// `prepare_out_path` + `open_out_leaf`, and driving that deterministically
/// needs a hook in the middle of a syscall pair. Read a green here as
/// "no component below the root is followed at the write", not as "the
/// window is measured".
#[cfg(unix)]
#[test]
fn a_swapped_ancestor_must_not_redirect_a_write() {
    let (_g, out, outside) = pathid_dirs("x508ancestor");
    let escaped = swap_the_ancestor(&out, &outside, "payload.bin");

    // The demonstration: the path-taking constructor walks straight
    // through, so a green below cannot be a swap that failed to take.
    let target = out.join("a").join("b").join("payload.bin");
    drop(nzbkit::disk::FileWriter::create_capped(
        &target,
        16,
        1 << 20,
    ));
    assert!(
        escaped.is_file(),
        "the swap did not take - this test would pass without a fix"
    );
    std::fs::remove_file(&escaped).unwrap();

    // The door the download and extraction paths now call.
    let w = nzbkit::disk::FileWriter::create_under(&out, "a/b/payload.bin", 16, 1 << 20);
    assert!(
        w.is_err(),
        "the root-anchored constructor accepted the swap"
    );
    assert!(
        !escaped.exists(),
        "the write followed an ancestor swapped after validation and \
         created {} outside the output directory",
        escaped.display()
    );
}

/// The other half of the same constructor, and the one a resumed job
/// takes: the non-truncating open must not be redirected either. Its
/// `preallocate_capped` is what resized an outside inode in X5-06, so
/// an escape here is a write even when the file already exists - which
/// is what the sentinel's LENGTH grades.
#[cfg(unix)]
#[test]
fn a_swapped_ancestor_must_not_redirect_a_resume_write() {
    let (_g, out, outside) = pathid_dirs("x508ancestorres");
    let escaped = swap_the_ancestor(&out, &outside, "payload.bin");
    let sentinel = plant_sentinel(escaped.parent().unwrap(), "payload.bin");
    let before = std::fs::metadata(&sentinel).unwrap().len();

    // The demonstration, on the resume arm: the path door resizes it.
    let target = out.join("a").join("b").join("payload.bin");
    drop(nzbkit::disk::FileWriter::create_resume_capped(
        &target,
        4096,
        1 << 20,
    ));
    assert_ne!(
        std::fs::metadata(&sentinel).unwrap().len(),
        before,
        "the swap did not take - this test would pass without a fix"
    );
    std::fs::write(&sentinel, SENTINEL).unwrap();
    let before = std::fs::metadata(&sentinel).unwrap().len();

    let w = nzbkit::disk::FileWriter::create_resume_under(&out, "a/b/payload.bin", 4096, 1 << 20);
    assert!(
        w.is_err(),
        "the root-anchored constructor accepted the swap"
    );
    let after = std::fs::metadata(&sentinel).unwrap().len();
    assert_eq!(
        after, before,
        "the resume open followed a swapped ancestor and resized an \
         outside inode ({before} -> {after} bytes)"
    );
    assert_eq!(std::fs::read(&sentinel).unwrap(), SENTINEL);
}

// ---------------------------------------------------------------- X5-19

/// X5-19: the case-sensitivity probe must not own a predictable
/// filename. It creates `.nzbfast-CaseProbe-<pid>-<seq>` with
/// `File::create` (truncating) and then deletes it - so a pre-existing
/// file at that exact name is destroyed by an unrelated capability
/// probe.
///
/// The seq counter is process-global, so the probe is driven ONCE first
/// to learn which index the next call will use; the sentinel is planted
/// at that name and the second call is the one graded.
#[test]
fn x5_19_the_case_probe_must_not_destroy_a_predictable_name() {
    let (_g, out, _outside) = pathid_dirs("x519probe");
    // Burn one index so the next name is derivable from the observed one.
    let _ = nzbkit::disk::case_insensitive_dir(&out);
    let used: Vec<String> = std::fs::read_dir(&out)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        used.is_empty(),
        "probe left files behind, so the seq cannot be derived: {used:?}"
    );

    // The next call takes the next seq. Plant every plausible index in
    // the small window ahead of it, so the probe's own choice is hit
    // without reaching into private state.
    let pid = std::process::id();
    let mut planted = Vec::new();
    for seq in 0..8u32 {
        let p = out.join(format!(".nzbfast-CaseProbe-{pid}-{seq}"));
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(SENTINEL).unwrap();
        planted.push(p);
    }

    let _ = nzbkit::disk::case_insensitive_dir(&out);

    let lost: Vec<String> = planted
        .iter()
        .filter(|p| std::fs::read(p).unwrap_or_default() != SENTINEL)
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    assert!(
        lost.is_empty(),
        "the case probe truncated or deleted pre-existing files at its \
         own predictable name: {lost:?}"
    );
}
