//! The spent-intermediate sweep and SPLIT containers.
//!
//! `sweep_spent_entry` lists this level's input archives with
//! `is_extractable_archive`, which is a per-PATH question. A split
//! container answers it on part 1 alone: part 1 carries the container's
//! signature and parts 2..=n are raw continuation bytes, with nothing to
//! sniff and - in the obfuscated shape - nothing in the name either. So
//! the sweep deleted the head and only the head, and a 62-part set
//! finished as 61 parts beside the payload: 5.9 GiB that can no longer
//! be retried, re-extracted or repaired, because the removed part is the
//! one carrying the start header.
//!
//! Measured on a plain split 7z past the holds slice
//! (`research/SEVENZ-PLAIN-HOLDS-2026-08-26.md` section 4). The
//! single-file arm of that same round removed its container in full, so
//! the two shapes disagreed about the same policy.
//!
//! Both real callers are exercised, because they answer differently by
//! design: depth 0 is the offline `nzbfast extract` CLI and the user's
//! own downloaded set, which this sweep never touches; depth 1 is the
//! post-download nested pass BOTH front ends run (`get::tail::unpack_tail`
//! calls it, and the daemon reaches that same tail through
//! `get_with_progress`), where the archives were materialized by our own
//! demote seconds ago and are scratch a one-pass job never writes.
use super::*;

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "nzbfast-splitsweep-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn names(dir: &std::path::Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// One plain (no password, no `-mhe`) 7z container over one member.
fn container_bytes(data: &[u8]) -> Vec<u8> {
    use sevenz_rust2::{ArchiveEntry, ArchiveWriter};
    let mut w = ArchiveWriter::new(std::io::Cursor::new(Vec::new())).unwrap();
    w.push_archive_entry(ArchiveEntry::new_file("movie.mkv"), Some(data))
        .unwrap();
    w.finish().unwrap().into_inner()
}

/// Cut `bytes` into `parts` numbered files - the byte split 7-Zip's
/// `-v` writes and the field posts.
fn split_into(dir: &std::path::Path, bytes: &[u8], parts: usize, stem: &str) {
    let cut = bytes.len().div_ceil(parts);
    for (i, chunk) in bytes.chunks(cut).enumerate() {
        std::fs::write(dir.join(format!("{stem}.{:03}", i + 1)), chunk).unwrap();
    }
}

/// The invariant, stated as the set rather than as a file count: what the
/// sweep leaves behind is never PART of a container - either the whole
/// set is there, or none of it is. 61 of 62 is the one end-state no
/// policy wants, and it is what shipped.
#[track_caller]
fn set_is_whole_or_gone(dir: &std::path::Path, stem: &str, parts: usize) {
    let left: Vec<String> = names(dir)
        .into_iter()
        .filter(|n| n.starts_with(&format!("{stem}.")))
        .collect();
    assert!(
        left.is_empty() || left.len() == parts,
        "the sweep left {} of {parts} parts - an incomplete set nothing can open: {left:?}",
        left.len()
    );
}

/// The named field shape, `<base>.7z.NNN`.
#[test]
fn a_split_7z_set_is_swept_whole_or_not_at_all() {
    let data: Vec<u8> = (0..150_000u32).map(|i| (i * 13 + 5) as u8).collect();
    let bytes = container_bytes(&data);

    // Depth 0 - the offline CLI and the user's own post. Nothing is swept
    // here at all, which is the existing contract this must not move.
    let dir = tmpdir("named-d0");
    split_into(&dir, &bytes, 3, "set.7z");
    assert_eq!(
        extract_nested(&dir, None, 0).unwrap(),
        NestOutcome::Produced
    );
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), data);
    set_is_whole_or_gone(&dir, "set.7z", 3);
    assert_eq!(
        names(&dir),
        vec![
            "movie.mkv".to_string(),
            "set.7z.001".into(),
            "set.7z.002".into(),
            "set.7z.003".into()
        ],
        "depth 0 must keep the downloaded set"
    );
    std::fs::remove_dir_all(&dir).unwrap();

    // Depth 1 - the post-download nested pass both front ends run. The
    // container is spent scratch, so it goes; the point is that it goes
    // WHOLE. Before the fix this left `set.7z.002` and `set.7z.003`.
    let dir = tmpdir("named-d1");
    split_into(&dir, &bytes, 3, "set.7z");
    assert_eq!(
        extract_nested(&dir, None, 1).unwrap(),
        NestOutcome::Produced
    );
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), data);
    set_is_whole_or_gone(&dir, "set.7z", 3);
    assert_eq!(
        names(&dir),
        vec!["movie.mkv".to_string()],
        "the spent container must leave in full, like the single-file arm"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The single-file arm of the same round, which is the behaviour the
/// split shape was failing to match. Pinned so the two can never drift
/// apart again in either direction.
#[test]
fn a_single_file_7z_and_a_split_one_reach_the_same_end_state() {
    let data: Vec<u8> = (0..90_000u32).map(|i| (i * 7 + 1) as u8).collect();
    let bytes = container_bytes(&data);

    let single = tmpdir("single-d1");
    std::fs::write(single.join("set.7z"), &bytes).unwrap();
    assert_eq!(
        extract_nested(&single, None, 1).unwrap(),
        NestOutcome::Produced
    );

    let split = tmpdir("split-d1");
    split_into(&split, &bytes, 4, "set.7z");
    assert_eq!(
        extract_nested(&split, None, 1).unwrap(),
        NestOutcome::Produced
    );

    assert_eq!(
        names(&single),
        names(&split),
        "one container, two postings, two different directories afterwards"
    );
    assert_eq!(names(&single), vec!["movie.mkv".to_string()]);
    std::fs::remove_dir_all(&single).unwrap();
    std::fs::remove_dir_all(&split).unwrap();
}

/// The obfuscated twin: the same container posted as `hash.001`,
/// `hash.002`, ... with nothing in the names saying 7z. Part 1 still
/// carries the signature, so it still answered `is_extractable_archive`
/// alone - the identical defect under a name the grammar has to work
/// harder for.
#[test]
fn an_obfuscated_split_set_is_swept_whole_or_not_at_all() {
    let data: Vec<u8> = (0..120_000u32).map(|i| (i * 11 + 2) as u8).collect();
    let bytes = container_bytes(&data);

    let dir = tmpdir("obf-d1");
    split_into(&dir, &bytes, 3, "hash");
    assert_eq!(
        extract_nested(&dir, None, 1).unwrap(),
        NestOutcome::Produced
    );
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), data);
    set_is_whole_or_gone(&dir, "hash", 3);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The CONTROL, and it is labelled one rather than dressed up as a
/// regression: it passes on the tree before the fix too. Two independent
/// sets at one level is the ambiguity `sweep_spent_entry` refuses
/// outright (`stems.len() != 1`), and what this pins is that widening
/// the delete to whole sets did not widen THAT - a set the pass never
/// proved spent must not lose parts to a neighbour's success.
///
/// The narrower property - that the expansion reaches only the set whose
/// own head was swept - is structural (`find(|s| s.contains(p))`) and is
/// deliberately NOT claimed as tested here: every fixture that would
/// distinguish it needs a split set whose head is absent from
/// `entry_archives` while exactly one stem survives, and a 7z or RAR head
/// is what puts a part 1 in that list to begin with. An over-broad
/// expansion was driven against this file and correctly went unreported,
/// which is why the limit is written down instead.
#[test]
fn two_sets_at_one_level_still_refuse_the_sweep() {
    let a: Vec<u8> = (0..70_000u32).map(|i| (i * 3 + 1) as u8).collect();
    let b: Vec<u8> = (0..70_000u32).map(|i| (i * 5 + 9) as u8).collect();
    let dir = tmpdir("two-sets");
    split_into(&dir, &container_bytes(&a), 3, "one.7z");
    split_into(&dir, &container_bytes(&b), 3, "two.7z");
    let _ = extract_nested(&dir, None, 1);
    set_is_whole_or_gone(&dir, "one.7z", 3);
    set_is_whole_or_gone(&dir, "two.7z", 3);
    assert_eq!(
        names(&dir).iter().filter(|n| n.contains(".7z.")).count(),
        6,
        "two sets cannot both be proven spent - neither may lose a part"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
