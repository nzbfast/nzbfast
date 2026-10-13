//! Codex sweep 13 Oct 2026 F4: a nested archive that shares the OUTER
//! set's name, in a directory the outer pass created.
//!
//! The descent guard exists so a volume REBUILT during extraction (.rev
//! reconstruction, RR repair) is not mistaken for a nested archive: it
//! lands in the after/before diff as a "new" file but belongs to the
//! outer set. It used to key that judgement on the bare release stem
//! (and, for magic-only sets, on one boolean for the whole tree), so a
//! poster's `release.rar -> sub/release.rar -> payload` read as a
//! rebuilt outer volume, nothing descended into `sub`, and the job
//! reported `Produced` with the payload still packed. A rebuilt volume
//! lands BESIDE its set, so the guard is keyed by (parent dir, stem) and
//! the magic-only census by directory.
//!
//! The end-to-end rows are the defect and its controls; the guard rows
//! pin the half no end-to-end fixture here can drive cheaply - a
//! genuinely rebuilt outer volume beside its set must still be refused
//! descent.
use super::*;
use crate::rarfixtures::{Member, stored_archive};

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "nzbfast-samestem-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Anywhere in the subtree: the ladder stages through `.nzbfast-nest`
/// and lifts back, and a level's output can land in a subfolder.
fn find_file(dir: &std::path::Path, name: &str) -> Option<PathBuf> {
    for e in std::fs::read_dir(dir).ok()?.flatten() {
        let p = e.path();
        if p.is_dir() {
            if let Some(hit) = find_file(&p, name) {
                return Some(hit);
            }
        } else if p.file_name().is_some_and(|n| n == name) {
            return Some(p);
        }
    }
    None
}

fn payload() -> Vec<u8> {
    (0..20_000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect()
}

/// `outer_name` holding `inner_path`, which holds `payload.txt`.
fn two_layer(d: &std::path::Path, outer_name: &str, inner_path: &str, body: &[u8]) {
    let inner = stored_archive(&[Member::bare(b"payload.txt", body)]);
    let outer = stored_archive(&[Member::bare(inner_path.as_bytes(), &inner)]);
    std::fs::write(d.join(outer_name), outer).unwrap();
}

fn assert_unpacked(d: &std::path::Path, body: &[u8]) {
    let got = find_file(d, "payload.txt").expect("the inner archive must be descended into");
    assert_eq!(std::fs::read(&got).unwrap(), body, "byte-exact payload");
}

/// THE DEFECT: same stem, new subdirectory.
#[test]
fn a_same_named_inner_rar_in_a_new_subdir_is_unpacked() {
    let d = tmpdir("same");
    let body = payload();
    two_layer(&d, "release.rar", "sub/release.rar", &body);
    assert_eq!(extract_nested(&d, None, 0).unwrap(), NestOutcome::Produced);
    assert_unpacked(&d, &body);
    std::fs::remove_dir_all(&d).unwrap();
}

/// Control: a differently named inner archive was always descended into.
#[test]
fn a_differently_named_inner_rar_in_a_new_subdir_is_unpacked() {
    let d = tmpdir("diff");
    let body = payload();
    two_layer(&d, "release.rar", "sub/different.rar", &body);
    assert_eq!(extract_nested(&d, None, 0).unwrap(), NestOutcome::Produced);
    assert_unpacked(&d, &body);
    std::fs::remove_dir_all(&d).unwrap();
}

/// The magic-only twin of the defect: an obfuscated outer volume used
/// to make EVERY new extensionless RAR in the tree read as a rebuilt
/// member, including one in a subdirectory the pass itself created.
#[test]
fn an_obfuscated_inner_rar_in_a_new_subdir_is_unpacked() {
    let d = tmpdir("obf");
    let body = payload();
    two_layer(
        &d,
        "0a1b2c3d4e5f60718293a4b5c6d7e8f9",
        "sub/f9e8d7c6b5a4938271605f4e3d2c1b0a",
        &body,
    );
    assert_eq!(extract_nested(&d, None, 0).unwrap(), NestOutcome::Produced);
    assert_unpacked(&d, &body);
    std::fs::remove_dir_all(&d).unwrap();
}

fn rar_head(p: &std::path::Path) {
    let mut data = b"Rar!\x1a\x07\x01\x00".to_vec();
    data.resize(4096, 0);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, data).unwrap();
}

/// Control: a volume rebuilt BESIDE its named set is still the outer
/// set's, never a nested archive - and the same stem one directory down
/// is not.
#[test]
fn a_rebuilt_named_volume_beside_its_set_is_not_descended_into() {
    let d = tmpdir("guard-named");
    rar_head(&d.join("release.part1.rar"));
    rar_head(&d.join("release.part2.rar"));
    let before = snapshot_recursive(&d).unwrap();
    let guard = OuterSetGuard::new(&before);

    let rebuilt = d.join("release.part3.rar");
    rar_head(&rebuilt);
    assert!(guard.is_rebuilt_named(&rebuilt));
    assert!(guard.is_rebuilt_member(&rebuilt));

    let nested = d.join("sub").join("release.rar");
    rar_head(&nested);
    assert!(!guard.is_rebuilt_named(&nested));
    assert!(!guard.is_rebuilt_member(&nested));
    std::fs::remove_dir_all(&d).unwrap();
}

/// Control: a magic-only set marks only ITS OWN directory. A new
/// extensionless RAR beside it is a rebuilt member; one in another
/// directory - created by the pass, or holding a separate obfuscated
/// set of its own - is not.
#[test]
fn a_magic_only_set_marks_only_its_own_directory() {
    let d = tmpdir("guard-obf");
    rar_head(&d.join("0a1b2c3d4e5f6071"));
    rar_head(&d.join("other").join("8293a4b5c6d7e8f9"));
    let before = snapshot_recursive(&d).unwrap();
    let guard = OuterSetGuard::new(&before);

    let beside = d.join("1a2b3c4d5e6f7081");
    rar_head(&beside);
    assert!(guard.is_rebuilt_member(&beside));
    let beside_other = d.join("other").join("9a8b7c6d5e4f3021");
    rar_head(&beside_other);
    assert!(guard.is_rebuilt_member(&beside_other));

    let fresh = d.join("sub").join("f9e8d7c6b5a49382");
    rar_head(&fresh);
    assert!(!guard.is_rebuilt_member(&fresh));
    std::fs::remove_dir_all(&d).unwrap();

    // ...and a magic-only set that lives ONLY in a subdirectory does not
    // mark the top level.
    let d = tmpdir("guard-obf-sep");
    rar_head(&d.join("other").join("8293a4b5c6d7e8f9"));
    let before = snapshot_recursive(&d).unwrap();
    let guard = OuterSetGuard::new(&before);
    let top = d.join("1a2b3c4d5e6f7081");
    rar_head(&top);
    assert!(!guard.is_rebuilt_member(&top));
    std::fs::remove_dir_all(&d).unwrap();
}
