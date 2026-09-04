//! The test seams `crates/nzbfast`'s own tests reach INTO this crate for.
//!
//! Everything here was in `testkit.rs` beside it and was `#[cfg(test)]`
//! while `smart` and `serve` were one crate. They are not any more
//! (crate-split step 3), and a `cfg(test)` item is invisible from
//! another crate whatever its visibility - so the choice at the cut was
//! this module or deleting the tests that take these.
//!
//! It is a SEPARATE file from `testkit.rs` rather than that module's
//! gate being widened, because testkit reaches `crate::testscratch`,
//! which is `#[cfg(test)] mod` and cannot be widened the same way: a
//! scratch guard whose sweep exists to run once per TEST process has no
//! meaning in a build that is not one. What is here instead is the
//! subset that composes only production items, so it holds under
//! `feature = "test-support"` with no test harness anywhere.
//!
//! `smart.rs` re-exports all four under the paths they always had, so
//! neither this crate's own test children nor `tests_jobs.rs`
//! names this module.

/// A minimal but well-formed PAR2 index: a Main packet listing one id
/// per member and a FileDesc for each. No IFSC and no recovery slices -
/// `Par2Set::parse` leaves `blocks` empty for a file with no IFSC
/// packet, and nothing that reads this asks about blocks.
///
/// SHARED rather than written out per caller, and that is the point of
/// it being here. `smart::setclaim`'s tests and `serve::naming`'s
/// authority tests both need a set that DECLARES a chosen filename, and
/// two hand-copied PAR2 writers in one crate are two spellings of one
/// packet grammar with nothing holding them in step - the copy-paste
/// sibling shape this repo keeps paying for. `identity.rs` keeps its
/// own for the one reason this home does not solve: that one is
/// `#[cfg(feature = "indexer")]`, and everything reached from here must
/// hold on the slim build too.
pub fn par2_index(set: u8, members: &[(&str, u64)]) -> Vec<u8> {
    use md5::Digest as _;
    let pkt = |ptype: &[u8; 16], body: &[u8]| -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(nzbkit::par2::MAGIC);
        p.extend_from_slice(&(64 + body.len() as u64).to_le_bytes());
        p.extend_from_slice(&[0u8; 16]); // packet MD5, patched below
        p.extend_from_slice(&[set; 16]); // recovery set id
        p.extend_from_slice(ptype);
        p.extend_from_slice(body);
        let md5: [u8; 16] = md5::Md5::digest(&p[32..]).into();
        p[16..32].copy_from_slice(&md5);
        p
    };
    let fid = |i: usize| -> [u8; 16] { [set.wrapping_add(i as u8).wrapping_add(1); 16] };
    let mut main = Vec::new();
    main.extend_from_slice(&4096u64.to_le_bytes());
    main.extend_from_slice(&(members.len() as u32).to_le_bytes());
    for i in 0..members.len() {
        main.extend_from_slice(&fid(i));
    }
    let mut out = pkt(b"PAR 2.0\0Main\0\0\0\0", &main);
    for (i, (name, len)) in members.iter().enumerate() {
        let mut d = Vec::new();
        d.extend_from_slice(&fid(i));
        d.extend_from_slice(&[set ^ (i as u8) ^ 0x40; 16]); // whole-file md5
        d.extend_from_slice(&[set ^ (i as u8) ^ 0x80; 16]); // md5_16k
        d.extend_from_slice(&len.to_le_bytes());
        d.extend_from_slice(name.as_bytes());
        while !d.len().is_multiple_of(4) {
            d.push(0);
        }
        out.extend(pkt(b"PAR 2.0\0FileDesc", &d));
    }
    out
}

// ---------------------------------------------------------------------
// The trash tests' process-global serialisation, moved out of smart.rs
// under the size gate (TODO 106) and out of testkit.rs by the
// crate-split step 3 cut. The per-fn `#[cfg(test)]` each of these
// carried inline is still dropped: the whole MODULE is gated, on
// `any(test, feature = "test-support")` now rather than on `test`.
//
// The lock below is a `static` and therefore ONE PER PROCESS, not one
// per crate: `crates/nzbfast`'s test binary links this crate, so its
// trash tests take the same `RwLock` as each other, and this crate's own
// take the same one as each other in their own process. Neither set can
// interleave with the other, because nothing links both into one
// process - which is what makes the split safe rather than merely
// compiling (`tools/test-global-gate.py` scores contention per crate for
// exactly this reason).
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
pub fn one_trash_test_at_a_time() -> std::sync::RwLockWriteGuard<'static, ()> {
    // Poison is nothing here: each test sets the flags it cares about on
    // the way in, so a panicking predecessor leaves nothing to inherit.
    crate::tools::RwLockExt::write_ok(trash_globals_lock())
}

/// Shared side, for tests whose deletes READ the trash globals: any test
/// that asserts what a `remove_user_file`-family delete left on disk.
/// Take it before creating fixtures and hold it past the last assert.
pub fn trash_globals_steady() -> std::sync::RwLockReadGuard<'static, ()> {
    crate::tools::RwLockExt::read_ok(trash_globals_lock())
}

/// Pretend every Trash route has given up, for tests that need a REFUSED
/// recoverable delete without a machine that has one. The refusal is the
/// interesting case - it is what leaves a user's download on disk after
/// they asked for it to go - and it is otherwise unreachable from a test:
/// the real latch only sets after a backend blows `TRASH_DEADLINE`.
///
/// Take [`one_trash_test_at_a_time`] first, and set it back on the way
/// out: this is the same process-global every other trash test reads.
/// Let a `$TMPDIR` path take the RECOVERABLE route, for a test whose
/// subject is what a recoverable delete does.
///
/// `under_temp_dir` refuses one by default and must keep doing so: the
/// binary an integration test spawns carries this crate's
/// `test-support` feature (a dev-dependency's features unify into the
/// bin built in the same cargo invocation), so a `cfg!(feature = ...)`
/// exemption there would switch the guard off in exactly the build it
/// was written for and hand back the macOS "-43" Finder dialog at all
/// 122 child-spawn sites. A DEFAULT-OFF runtime seam cannot: nothing
/// sets it but a test that asks.
///
/// `smart`'s own trash tests do not need it - they run under
/// `cfg(test)`, which exempts them directly. Its one caller is
/// `crates/nzbfast`'s `a_refused_delete_keeps_the_files_and_says_why`,
/// a crate away since the step 3 cut. Take [`one_trash_test_at_a_time`]
/// first and set it back on the way out, like every flag in here.
pub fn force_temp_trash(v: bool) {
    super::TEMP_TRASH_FORCED.store(v, std::sync::atomic::Ordering::Relaxed);
}

pub fn force_trash_unresponsive(v: bool) {
    super::TRASH_UNRESPONSIVE.store(v, std::sync::atomic::Ordering::Relaxed);
}
