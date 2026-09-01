//! Helpers shared by both of `smart`'s test children. They live here
//! rather than in either one because the filing cases and the rename
//! cases both build scratch trees and both hold emitted names to the
//! portability rules - and a module cannot borrow a sibling's fn.

use super::*;

// The integration suites' scratch guard, reached through the crate's
// single include of it (`crate::testscratch`) rather than a second
// `#[path]` of the same file - two includes are two copies of the type
// and two sweep latches. TODO 149: scratch() used to remove only the
// PREVIOUS run's dir and leak its own, which is what gave the §142
// oversized fixture a run-long blast radius on NTFS.
pub(super) use crate::testscratch::ScratchDir;

pub(super) fn scratch(tag: &str) -> ScratchDir {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let d = std::env::temp_dir().join(format!("nzbfast-smart-{}-{tag}-{n}", std::process::id()));
    ScratchDir::attach(&d)
}

/// The §149 contract itself: a passing test's tree is gone when the
/// guard drops.
#[test]
fn scratch_removes_its_tree_on_drop() {
    let d = scratch("dropclean");
    let kept = d.to_path_buf();
    std::fs::write(d.join("f"), b"x").unwrap();
    drop(d);
    assert!(!kept.exists(), "scratch tree must be removed on drop");
}

/// The other half of the contract: a FAILING test keeps its tree, so
/// the evidence of the failure survives for whoever is debugging it.
#[test]
fn scratch_keeps_its_tree_when_the_test_panics() {
    let kept = std::sync::Arc::new(std::sync::Mutex::new(None::<PathBuf>));
    let seen = kept.clone();
    let r = std::panic::catch_unwind(move || {
        let d = scratch("panickeep");
        *seen.lock().unwrap() = Some(d.to_path_buf());
        std::fs::write(d.join("evidence"), b"x").unwrap();
        panic!("the failing test");
    });
    assert!(r.is_err(), "the closure must have panicked");
    let path = kept.lock().unwrap().take().unwrap();
    assert!(
        path.join("evidence").exists(),
        "a panicking test's tree must survive its guard"
    );
    let _ = std::fs::remove_dir_all(&path);
}

/// The bytes of a genuine AppleDouble: the `0x00051607` magic, the
/// version word, and a short body standing in for a resource fork.
///
/// A `._name` is only a Finder dropping if it LOOKS like one - the
/// prefix is a convention and a payload can carry it (M4-68), so
/// `is_finder_dropping` reads the magic and `b"resource fork"` is no
/// longer an AppleDouble. Every test that means "the genuine article"
/// takes its bytes from here, so the fixture and the predicate cannot
/// drift apart.
pub(super) fn appledouble_bytes() -> Vec<u8> {
    let mut v = vec![0x00, 0x05, 0x16, 0x07, 0x00, 0x02, 0x00, 0x00];
    v.extend_from_slice(&[0u8; 16]); // filler
    v.extend_from_slice(&[0x00, 0x02]); // entry count
    v.extend_from_slice(b"resource fork");
    v
}

/// The bytes of a genuine `.DS_Store`: the version word, the `Bud1`
/// magic of the B-tree store, and a short body standing in for it.
///
/// Same contract as [`appledouble_bytes`], and for the same reason
/// (M4-79): `.DS_Store` was the last name-only permanent delete in the
/// Finder-dropping pass, so `is_finder_dropping` now reads these eight
/// bytes and a run of zeroes at the size a real one happens to be is no
/// longer one. Every test that means "the genuine article" takes its
/// bytes from here, so the fixture and the predicate cannot drift apart.
/// 6148 is what Finder writes for a folder it has merely looked at,
/// kept because two existing prune pins are about a husk that size.
pub(super) fn ds_store_bytes() -> Vec<u8> {
    let mut v = vec![0x00, 0x00, 0x00, 0x01, b'B', b'u', b'd', b'1'];
    v.resize(6148, 0);
    v
}

/// A single emitted path component, held to the rules a Windows box
/// or an SMB share applies - which is every finished tree's fate, so
/// the host that wrote the name is beside the point.
pub(super) fn assert_portable(name: &str) {
    assert!(!name.is_empty(), "empty component");
    assert!(!name.starts_with('.'), "hidden: {name:?}");
    assert!(
        !name.ends_with('.') && !name.ends_with(' '),
        "Windows truncates: {name:?}"
    );
    assert!(!name.starts_with(' '), "leading space: {name:?}");
    assert!(!name.contains(':'), "drive/ADS meaning: {name:?}");
    let stem = name.split('.').next().unwrap_or(name).to_ascii_uppercase();
    assert!(
        !matches!(
            stem.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "COM1" | "LPT1"
        ),
        "reserved device: {name:?}"
    );
}

// ---------------------------------------------------------------------
// The trash tests' process-global serialisation, moved out of smart.rs
// under the size gate (TODO 106). Test-only code in a test-only module,
// so the per-fn #[cfg(test)] each of these carried inline is dropped:
// `mod testkit` is already gated. smart.rs re-exports them, so both the
// sibling test children and serve/tests_jobs.rs reach them unchanged.
/// The flags below are process-global and the trash tests write them, so
/// those tests take this first and run one at a time. Without it `cargo
/// test` runs them together and one test's latch - or its reset - lands
/// inside another test's delete: `a_junk_delete_is_recoverable_and_the_
/// opt_out_is_not` then finds its fixture hard-deleted rather than binned.
/// Lives out here, not in one test module, because both of them need it.
///
/// A writer excluding only other writers was not enough: every delete in
/// the suite READS these globals (`delete_to_trash` at its entry, the
/// latch inside the gate), so a delete-asserting test that overlapped a
/// writer's window saw `TRASH` on and its delete came back refused - the
/// file it asserted gone was still there, roughly one full-suite run in
/// four. Worse, a reader that caught the window made a REAL Trash call,
/// which set `TRASH_ANSWERED` under nobody's lock and broke
/// `concurrent_callers_probe_a_dead_trash_only_once` from across the
/// module. So this is a reader-writer lock: flag-writing tests take the
/// write side, and every test whose delete reads the flags holds
/// [`trash_globals_steady`] across the delete and its asserts - shared
/// among themselves, exclusive against any writer.
fn trash_globals_lock() -> &'static std::sync::RwLock<()> {
    static SERIAL: std::sync::RwLock<()> = std::sync::RwLock::new(());
    &SERIAL
}

/// Exclusive side, for tests that WRITE the trash globals.
pub(crate) fn one_trash_test_at_a_time() -> std::sync::RwLockWriteGuard<'static, ()> {
    // Poison is nothing here: each test sets the flags it cares about on
    // the way in, so a panicking predecessor leaves nothing to inherit.
    crate::RwLockExt::write_ok(trash_globals_lock())
}

/// Shared side, for tests whose deletes READ the trash globals: any test
/// that asserts what a `remove_user_file`-family delete left on disk.
/// Take it before creating fixtures and hold it past the last assert.
pub(crate) fn trash_globals_steady() -> std::sync::RwLockReadGuard<'static, ()> {
    crate::RwLockExt::read_ok(trash_globals_lock())
}

/// Pretend every Trash route has given up, for tests that need a REFUSED
/// recoverable delete without a machine that has one. The refusal is the
/// interesting case - it is what leaves a user's download on disk after
/// they asked for it to go - and it is otherwise unreachable from a test:
/// the real latch only sets after a backend blows `TRASH_DEADLINE`.
///
/// Take [`one_trash_test_at_a_time`] first, and set it back on the way
/// out: this is the same process-global every other trash test reads.
pub(crate) fn force_trash_unresponsive(v: bool) {
    TRASH_UNRESPONSIVE.store(v, std::sync::atomic::Ordering::Relaxed);
}
