//! The disk tar arm's own suite: what it unpacks, and every shape it
//! refuses whole rather than half-extracting.
//!
//! A sibling file rather than an inline `mod tests` so `tar.rs` stays
//! well inside its size-gate headroom (the `extract/tar.rs` pattern).

use super::*;
use nzbkit::tar::fixtures::{Spec, tar_of};

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("nzbfast-tarx-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Write `bytes` into `dir` as `name` and answer the path.
fn put(dir: &std::path::Path, name: &str, bytes: &[u8]) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, bytes).unwrap();
    p
}

/// The ordinary shape: two files and a subdirectory member, unpacked in
/// place, byte-exact, with the container left where it was (removing it
/// is the spent-intermediate sweep's call, not this arm's).
#[test]
fn a_plain_tar_unpacks_where_it_lies() {
    let dir = tmp("plain");
    let movie = vec![7u8; 40_000];
    let readme = b"release notes\n".repeat(50);
    let arch = tar_of(&[
        Spec::file("movie.mkv", &movie),
        Spec::dir("sub/"),
        Spec::file("sub/notes.txt", &readme),
    ]);
    let container = put(&dir, "release.tar", &arch);

    let jobs = collect_tar_containers(&dir).unwrap();
    assert_eq!(jobs, vec![container.clone()]);
    assert!(extract_tar(&dir, &jobs).is_empty(), "nothing may decline");

    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), movie);
    assert_eq!(std::fs::read(dir.join("sub/notes.txt")).unwrap(), readme);
    assert!(
        container.exists(),
        "the container is not this arm's to remove"
    );
}

/// An empty member is a real member: the file has to appear, at zero
/// bytes, rather than being skipped by a copy loop that never runs.
#[test]
fn an_empty_member_lands_as_an_empty_file() {
    let dir = tmp("empty");
    let arch = tar_of(&[Spec::file("marker", b""), Spec::file("a.bin", &[1u8; 600])]);
    put(&dir, "release.tar", &arch);

    let jobs = collect_tar_containers(&dir).unwrap();
    assert!(extract_tar(&dir, &jobs).is_empty());
    assert_eq!(std::fs::metadata(dir.join("marker")).unwrap().len(), 0);
}

/// Each refusal condemns the whole container: the arm answers the
/// container as declined, and NOTHING it had already read is published
/// beside it. The staging dir carries that guarantee, so the assertion
/// that matters is the absence of `first.bin`, which sits ahead of the
/// refused member in every one of these archives.
#[test]
fn a_refused_member_leaves_the_container_packed_and_nothing_beside_it() {
    // (tag, the member that is refused)
    let cases: &[(&str, Spec<'_>)] = &[
        ("symlink", Spec::special("latest", b'2')),
        ("hardlink", Spec::special("dup", b'1')),
        ("device", Spec::special("null", b'3')),
        ("fifo", Spec::special("pipe", b'6')),
        ("sparse", Spec::special("holey.img", b'S')),
    ];
    let first = vec![3u8; 2_000];
    for (tag, bad) in cases {
        let dir = tmp(tag);
        let arch = tar_of(&[Spec::file("first.bin", &first), bad.clone()]);
        let container = put(&dir, "release.tar", &arch);
        let jobs = collect_tar_containers(&dir).unwrap();
        assert_eq!(
            extract_tar(&dir, &jobs),
            vec![container.clone()],
            "{tag} must decline the container"
        );
        assert!(container.exists(), "{tag}: the container must survive");
        assert!(
            !dir.join("first.bin").exists(),
            "{tag}: a refusal must publish nothing"
        );
    }
}

/// The pax spelling of a sparse member hides behind an ordinary file
/// header, so it is the one that would be extracted wrongly rather than
/// simply refused: the reader has to catch the keyword.
#[test]
fn a_pax_spelled_sparse_member_is_refused_too() {
    let dir = tmp("paxsparse");
    let mut sparse = Spec::file("holey.img", b"1234");
    sparse.pax = vec![
        ("GNU.sparse.major".to_string(), "1".to_string()),
        ("GNU.sparse.size".to_string(), "1048576".to_string()),
    ];
    let container = put(&dir, "release.tar", &tar_of(&[sparse]));
    let jobs = collect_tar_containers(&dir).unwrap();
    assert_eq!(extract_tar(&dir, &jobs), vec![container]);
    assert!(!dir.join("holey.img").exists());
}

/// A member naming a path outside the output directory is refused, not
/// clamped: the same rule the zip and 7z arms keep.
#[test]
fn an_entry_escaping_the_directory_is_refused() {
    let dir = tmp("escape");
    let container = put(
        &dir,
        "release.tar",
        &tar_of(&[Spec::file("../evil.sh", b"rm -rf /\n")]),
    );
    let jobs = collect_tar_containers(&dir).unwrap();
    assert_eq!(extract_tar(&dir, &jobs), vec![container]);
    assert!(!dir.parent().unwrap().join("evil.sh").exists());
}

/// A container cut BETWEEN members: every member in it is perfectly
/// well-formed, and only the missing end-of-archive block says the
/// archive was truncated. Without that test the arm would publish a cut
/// download as a complete one.
#[test]
fn a_container_cut_between_members_is_refused() {
    let dir = tmp("cut");
    let a = vec![5u8; 1_024];
    let b = vec![6u8; 1_024];
    let mut arch = tar_of(&[Spec::file("a.bin", &a), Spec::file("b.bin", &b)]);
    // Drop the two end-of-archive blocks and the whole second member.
    arch.truncate(nzbkit::tar::BLOCK + a.len());
    let container = put(&dir, "release.tar", &arch);
    let jobs = collect_tar_containers(&dir).unwrap();
    assert_eq!(extract_tar(&dir, &jobs), vec![container]);
    assert!(
        !dir.join("a.bin").exists(),
        "a cut archive publishes nothing"
    );
}

/// A container cut inside a member's DATA is caught by the member's own
/// declared size, which is the other half of the truncation story.
#[test]
fn a_container_cut_inside_a_member_is_refused() {
    let dir = tmp("cutdata");
    let a = vec![5u8; 16_384];
    let mut arch = tar_of(&[Spec::file("a.bin", &a)]);
    // Comfortably over the three-block floor the collector needs, so
    // this measures the REFUSAL and not the sniff declining to claim.
    arch.truncate(nzbkit::tar::BLOCK + 4_000);
    let container = put(&dir, "release.tar", &arch);
    let jobs = collect_tar_containers(&dir).unwrap();
    assert_eq!(extract_tar(&dir, &jobs), vec![container]);
}

/// A tar carrying no regular member at all is a refusal, not a success
/// that produced nothing.
#[test]
fn a_tar_holding_only_directories_is_refused() {
    let dir = tmp("dirsonly");
    let container = put(
        &dir,
        "release.tar",
        &tar_of(&[Spec::dir("a/"), Spec::dir("b/")]),
    );
    let jobs = collect_tar_containers(&dir).unwrap();
    assert_eq!(extract_tar(&dir, &jobs), vec![container]);
}

/// What the collector will and will not claim. The name gate is the
/// chase's own, so an obfuscated extensionless post counts and a NAMED
/// file that is not a `.tar` never reaches the sniff at all - which is
/// what keeps a payload container (`.cbz`, `.cb7`) out of this arm
/// without a list of its own.
#[test]
fn the_collector_claims_tar_and_extensionless_only() {
    let dir = tmp("collect");
    let arch = tar_of(&[Spec::file("a.bin", &[1u8; 2_000])]);
    let named = put(&dir, "release.tar", &arch);
    let obfuscated = put(&dir, "a1b2c3d4e5", &arch);
    // Tar bytes under a name that means something else: never claimed.
    put(&dir, "comic.cbz", &arch);
    put(&dir, "sidecar.bin", &arch);
    // Too small to be a tar at all, and a file with no ustar magic.
    put(&dir, "stub", &[0u8; 700]);
    put(&dir, "plain", &vec![9u8; 4_096]);

    let mut want = vec![obfuscated, named];
    want.sort();
    assert_eq!(collect_tar_containers(&dir).unwrap(), want);
}

/// A header whose stored checksum does not match is not a tar this arm
/// will open, even under a `.tar` name: the sniff verifies the whole
/// block, not the six magic bytes.
#[test]
fn a_bad_header_checksum_is_not_claimed() {
    let dir = tmp("badsum");
    let mut spec = Spec::file("a.bin", &[1u8; 2_000]);
    spec.bad_checksum = true;
    put(&dir, "release.tar", &tar_of(&[spec]));
    assert!(collect_tar_containers(&dir).unwrap().is_empty());
}

/// GNU's magic is the other half of the field, and its long-name entry
/// is the spelling a deep path arrives under. Both go through the same
/// reader, so this pins that the ARM drives it rather than re-deriving
/// the grammar.
#[test]
fn a_gnu_tar_with_a_long_name_unpacks() {
    let dir = tmp("gnu");
    let deep = format!("{}/movie.mkv", "nested".repeat(20));
    let body = vec![4u8; 3_000];
    let mut spec = Spec::file("truncated-name", &body);
    spec.gnu = true;
    spec.long_name = Some(&deep);
    put(&dir, "release.tar", &tar_of(&[spec]));
    let jobs = collect_tar_containers(&dir).unwrap();
    assert!(extract_tar(&dir, &jobs).is_empty());
    assert_eq!(std::fs::read(dir.join(&deep)).unwrap(), body);
}

/// The nested-layer predicate answers for a tar the same way it answers
/// for a 7z: a container to descend into, and (at depth) a spent
/// intermediate the sweep may remove once its payload sits beside it.
#[test]
fn a_tar_reads_as_an_extractable_archive() {
    let dir = tmp("predicate");
    let arch = tar_of(&[Spec::file("a.bin", &[1u8; 2_000])]);
    assert!(crate::is_extractable_archive(&put(
        &dir,
        "release.tar",
        &arch
    )));
    assert!(crate::is_extractable_archive(&put(&dir, "obf", &arch)));
    assert!(!crate::is_extractable_archive(&put(&dir, "c.cbz", &arch)));
    assert!(!crate::is_extractable_archive(&put(
        &dir,
        "plain.txt",
        b"not an archive"
    )));
}
