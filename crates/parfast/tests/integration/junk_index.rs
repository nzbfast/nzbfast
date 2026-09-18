//! The named `.par2` is junk and its volumes are not.
//!
//! par2cmdline does not stop at the file it was named: it loads that
//! one, then globs `<stem>*.par2` and loads each of those, and it
//! repeats the whole critical block through EVERY volume. So an index
//! overwritten with junk while its volumes sit intact beside it is a set
//! the reference repairs - measured 17 Sep 2026 against
//! par2cmdline v1.3.0, `r set.par2 '*'` reaches "Repair complete." and
//! exits 0 - and parfast used to decline the whole run with "You must
//! specify a Recovery file.", because `verify::locate` read only the
//! file it was named and gave up when those bytes carried no set id.
//!
//! That is a drop-in divergence with a job behind it: SABnzbd hands the
//! par2 it downloaded first, and a few bad articles in the index are the
//! ordinary reason it is junk.
//!
//! # What these tests pin, and why the last two matter most
//!
//! The rescue is easy to write too wide. A directory holding two sets is
//! the ordinary shape of a season folder, and `<stem>*.par2` reaches a
//! neighbour whose name merely EXTENDS the stem
//! (`Show.S01E01.Extra.par2` beside `Show.S01E01.par2`) - so a rule that
//! takes the first set id it finds repairs somebody else's files. The
//! reference does exactly that: on the directory
//! `a_junked_index_never_adopts_a_prefix_neighbours_set` builds,
//! par2cmdline v1.3.0 adopts whichever set its readdir reached first,
//! prints "There are 1 recoverable files", verifies the OTHER release
//! and exits 0 with the damaged member untouched. `verify::sibling_set_id`
//! asks only siblings whose own `set_stem` matches, and takes their
//! answer only if they agree, so this lane repairs the damaged member
//! instead.
//!
//! And the refusal has to survive: `Main packet not found.` with exit 4
//! is SABnzbd's cue to fetch a DIFFERENT par2 out of the NZB and retry
//! (`newsunpack.py`, `par2cmdline_verify`), and `tools/sab-parser-gate.py`
//! records it as reached. A set with no usable `.par2` anywhere must
//! still answer it.
//!
//! Self-contained: the sets are made with parfast's own `c`, which
//! writes the critical block into every volume the way par2cmdline does
//! (`creator_packet.rs` is what holds that claim), so nothing here needs
//! the reference binary.

use std::path::Path;
use std::process::Command;

use crate::scratch::scratch;

fn parfast(dir: &Path, args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_parfast"))
        .args(args)
        .current_dir(dir)
        .env("NZBFAST_NO_ENRICH", "1")
        .output()
        .expect("parfast runs");
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap_or(-1), text)
}

/// Deterministic bytes: a test that damages a file has to be able to say
/// the repair put the SAME bytes back, and random ones would only say
/// the two reads agreed.
fn payload(n: usize, seed: u32) -> Vec<u8> {
    (0..n as u32)
        .map(|i| (i.wrapping_mul(seed | 1) ^ (i >> 5)) as u8)
        .collect()
}

fn write(dir: &Path, name: &str, bytes: &[u8]) {
    std::fs::write(dir.join(name), bytes).expect("write");
}

fn create(dir: &Path, set: &str, members: &[&str]) {
    let mut args = vec!["c", "-s2048", "-c8", set];
    args.extend_from_slice(members);
    let (code, text) = parfast(dir, &args);
    assert_eq!(code, 0, "create {set} failed:\n{text}");
}

/// Every byte of a `.par2` replaced with zero - which is how
/// `tools/sab-parser-gate.py`'s `corrupt-par2` fixture damages one, and
/// unlike random bytes it cannot accidentally frame a packet.
fn junk(dir: &Path, name: &str) {
    let path = dir.join(name);
    let len = std::fs::metadata(&path).expect("stat").len() as usize;
    std::fs::write(&path, vec![0u8; len]).expect("junk");
}

/// A run of bytes inverted in place: enough to lose blocks, not enough
/// to outrun the parity.
fn damage(dir: &Path, name: &str, at: usize, len: usize) {
    let path = dir.join(name);
    let mut bytes = std::fs::read(&path).expect("read");
    for b in &mut bytes[at..at + len] {
        *b = !*b;
    }
    std::fs::write(&path, bytes).expect("damage");
}

fn bytes(dir: &Path, name: &str) -> Vec<u8> {
    std::fs::read(dir.join(name)).expect("read")
}

/// The defect itself: the index is junk, the volumes are not, and the
/// set is entirely recoverable.
#[test]
fn a_junk_index_repairs_off_its_sibling_volumes() {
    let dir = scratch("junk-index-repairs");
    let member = payload(60_000, 0x9e37);
    write(&dir, "data.bin", &member);
    create(&dir, "set.par2", &["data.bin"]);

    damage(&dir, "data.bin", 1_000, 5_000);
    junk(&dir, "set.par2");

    let (code, text) = parfast(&dir, &["r", "set.par2"]);
    assert_eq!(code, 0, "repair refused:\n{text}");
    assert!(text.contains("Repair complete."), "{text}");
    assert_eq!(
        bytes(&dir, "data.bin"),
        member,
        "the member was not restored"
    );
}

/// The arm this change sits in FRONT of, and must leave alone: when no
/// sibling can supply the set id either, the run still answers the
/// reference's `Main packet not found.` and exit 4 - SABnzbd's cue to
/// fetch another par2 and retry.
#[test]
fn no_usable_par2_anywhere_still_answers_main_packet_not_found() {
    let dir = scratch("junk-index-all-bad");
    write(&dir, "data.bin", &payload(40_000, 0x1234));
    create(&dir, "set.par2", &["data.bin"]);

    let names: Vec<String> = std::fs::read_dir(&dir)
        .expect("read_dir")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.to_ascii_lowercase().ends_with(".par2"))
        .collect();
    assert!(names.len() > 1, "expected volumes beside the index");
    for name in &names {
        junk(&dir, name);
    }

    let (code, text) = parfast(&dir, &["r", "set.par2"]);
    assert_eq!(code, 4, "{text}");
    assert!(text.contains("Main packet not found."), "{text}");
}

/// A neighbour whose name EXTENDS the stem is inside `<stem>*.par2` and
/// is not this set. Its volumes must not be able to answer for a junked
/// index - which is what taking the first set id off the glob would do,
/// and what the reference itself does here.
#[test]
fn a_junked_index_never_adopts_a_prefix_neighbours_set() {
    let dir = scratch("junk-index-two-sets");
    let mine = payload(60_000, 0xa5a5);
    let theirs = payload(50_000, 0x5a5a);
    write(&dir, "mine.bin", &mine);
    write(&dir, "theirs.bin", &theirs);
    create(&dir, "Show.S01E01.par2", &["mine.bin"]);
    create(&dir, "Show.S01E01.Extra.par2", &["theirs.bin"]);

    damage(&dir, "mine.bin", 500, 5_000);
    junk(&dir, "Show.S01E01.par2");

    let (code, text) = parfast(&dir, &["r", "Show.S01E01.par2"]);
    assert_eq!(code, 0, "repair refused:\n{text}");
    assert!(text.contains("Repair complete."), "{text}");
    assert_eq!(
        bytes(&dir, "mine.bin"),
        mine,
        "the named set was not repaired"
    );
    assert_eq!(
        bytes(&dir, "theirs.bin"),
        theirs,
        "the neighbour was touched"
    );
}

/// The same directory with the index INTACT, which is the ordinary
/// season-folder shape and never reaches the fallback at all: it still
/// repairs the set it was pointed at and leaves the other alone.
#[test]
fn two_sets_in_one_directory_repair_the_one_they_were_pointed_at() {
    let dir = scratch("two-sets-good-index");
    let mine = payload(60_000, 0xbeef);
    let theirs = payload(50_000, 0xfeed);
    write(&dir, "mine.bin", &mine);
    write(&dir, "theirs.bin", &theirs);
    create(&dir, "Show.S01E01.par2", &["mine.bin"]);
    create(&dir, "Show.S01E01.Extra.par2", &["theirs.bin"]);

    damage(&dir, "mine.bin", 500, 5_000);
    damage(&dir, "theirs.bin", 700, 5_000);

    let (code, text) = parfast(&dir, &["r", "Show.S01E01.par2"]);
    assert_eq!(code, 0, "repair refused:\n{text}");
    assert_eq!(
        bytes(&dir, "mine.bin"),
        mine,
        "the named set was not repaired"
    );
    assert_ne!(
        bytes(&dir, "theirs.bin"),
        theirs,
        "the other set was repaired by a run that was not pointed at it"
    );
}
