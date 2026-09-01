//! The collision ladders that move an occupant aside compose a
//! `<prefix>-<n>-` onto a member's OWN name.
//!
//! That name is a [`nzbkit::disk::sanitize_out_name`] result, so for a
//! long posted name it is EXACTLY the 255-byte component cap - capping
//! is what produced it - and a prefix on top of that is a name no
//! filesystem creates (measured on APFS 31 Aug 2026: 255 creates, 256 is
//! `ENAMETOOLONG`). The ladder does not spin on it, which is the part
//! that hides it: `symlink_metadata` answers Err for a name too long to
//! look up, and the ladder reads Err as free - so it hands back the
//! unwritable name at the first rung and the `rename` is what fails,
//! leaving the member behind.
//!
//! A child module because `unpack.rs` sits inside 17% of its size-gate
//! ceiling and every other test group here is one too.

use super::*;

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "nzbfast-liftcap-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// The premise, asserted rather than assumed: any name past the cap
/// comes back at exactly the cap.
fn at_cap() -> String {
    let name = nzbkit::disk::sanitize_out_name(&format!("{}.bin", "y".repeat(400)));
    assert_eq!(name.len(), 255, "the premise moved");
    name
}

#[test]
fn a_scratch_member_at_the_cap_is_lifted_past_an_occupied_name() {
    let dir = tmpdir("lift");
    let sub = dir.join("scratch");
    std::fs::create_dir_all(&sub).unwrap();
    let name = at_cap();

    // The destination name is taken by something else, so the member
    // has to go to a disambiguated one.
    std::fs::write(dir.join(&name), b"incumbent").unwrap();
    std::fs::write(sub.join(&name), b"the member").unwrap();

    assert!(
        lift_scratch_into(&sub, &dir, "extracted", "test lift"),
        "the lift must report clean"
    );

    assert_eq!(
        std::fs::read(dir.join(&name)).unwrap(),
        b"incumbent",
        "the occupant keeps its name"
    );
    // Files only: `lift_scratch_into` empties the scratch directory but
    // leaves it standing - removing it is the caller's move.
    let lifted: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n != &name)
        .collect();
    assert_eq!(
        lifted.len(),
        1,
        "the member must land somewhere: {lifted:?}"
    );
    assert!(
        lifted[0].len() <= 255,
        "{} bytes: {}",
        lifted[0].len(),
        lifted[0]
    );
    assert_eq!(std::fs::read(dir.join(&lifted[0])).unwrap(), b"the member");
    // And the source is emptied, which is what "clean" is about.
    assert_eq!(std::fs::read_dir(&sub).unwrap().count(), 0);

    let _ = std::fs::remove_dir_all(&dir);
}

/// Nothing that works today moves: inside the cap the ladder is still
/// the plain `format!`, byte for byte.
#[test]
fn an_ordinary_name_keeps_its_plain_ladder_rung() {
    let dir = tmpdir("plain");
    let sub = dir.join("scratch");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(dir.join("episode.mkv"), b"incumbent").unwrap();
    std::fs::write(sub.join("episode.mkv"), b"the member").unwrap();

    assert!(lift_scratch_into(&sub, &dir, "extracted", "test lift"));
    assert_eq!(
        std::fs::read(dir.join("extracted-1-episode.mkv")).unwrap(),
        b"the member"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
