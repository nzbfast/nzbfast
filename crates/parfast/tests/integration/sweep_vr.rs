//! The verify + repair findings of the 9 Nov 2026 parfast sweep, each
//! pinned through the built binary on a set made by parfast's own `c`.
//!
//! * A1  - a member the Main packet declares with no usable FileDesc
//!   must not verify as "All files are correct" (exit 0, and `-p`
//!   purging the recovery files).
//! * A11 - `-B` naming the set's own directory under another spelling
//!   is that directory, not a refusal.
//! * A12 - the volumes of `movie.par2` are found when they are spelt
//!   `Movie.vol*.par2`.
//! * A13 - a donor named on the command line is asked before "Repair is
//!   not possible.".
//! * A19 - a crafted FileDesc length must not abort the verify on an
//!   allocation.
//! * A22 - an Unrepairable verdict leaves no `<name>.1` copies behind.
//! * B   - `-O` does not hand an empty stray file to a zero-length member.
//!
//! Self-contained: nothing here needs the reference binary.

use std::path::Path;
use std::process::Command;

use nzbkit::md5fast::{Digest, Md5};

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
    // A signal (an abort on allocation failure among them) has no code:
    // -1 is never a dialect exit, so it fails every assertion on one.
    (out.status.code().unwrap_or(-1), text)
}

fn payload(n: usize, seed: u32) -> Vec<u8> {
    (0..n as u32)
        .map(|i| (i.wrapping_mul(seed | 1) ^ (i >> 5)) as u8)
        .collect()
}

/// Bytes with no repeating block, for a test that needs damage to STAY
/// damage: [`payload`] repeats with a short period, so the engine finds
/// every lost block intact elsewhere in the same member and repairs with
/// no parity at all.
fn noise(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

fn write(dir: &Path, name: &str, bytes: &[u8]) {
    std::fs::write(dir.join(name), bytes).expect("write");
}

fn create(dir: &Path, args: &[&str]) {
    let mut all = vec!["c", "-s2048"];
    all.extend_from_slice(args);
    let (code, text) = parfast(dir, &all);
    assert_eq!(code, 0, "create failed:\n{text}");
}

fn par2_files(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .expect("read_dir")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.to_ascii_lowercase().ends_with(".par2"))
        .collect();
    v.sort();
    v
}

fn damage(dir: &Path, name: &str, at: usize, len: usize) {
    let path = dir.join(name);
    let mut bytes = std::fs::read(&path).expect("read");
    for b in &mut bytes[at..at + len] {
        *b = !*b;
    }
    std::fs::write(&path, bytes).expect("damage");
}

const MAGIC: &[u8; 8] = b"PAR2\0PKT";
const TYPE_FILEDESC: &[u8; 16] = b"PAR 2.0\0FileDesc";

/// Rewrite every `.par2` in `dir` packet by packet: `edit` sees each
/// FileDesc packet's member name and its whole packet, and answers
/// `false` to drop it. The packet MD5 is resealed after an edit, so the
/// parser accepts what was written. A deliberately dumb walk, for the
/// reason `creator_packet.rs` gives: borrowing the engine's parser would
/// let one mistake agree with itself.
fn rewrite_filedescs(dir: &Path, edit: impl Fn(&str, &mut Vec<u8>) -> bool) {
    replace_filedescs(dir, |member, pkt| {
        let mut pkt = pkt.to_vec();
        if edit(member, &mut pkt) {
            vec![pkt]
        } else {
            Vec::new()
        }
    });
}

/// The general form of [`rewrite_filedescs`]: every FileDesc packet is
/// replaced by whatever `edit` returns for it - none, itself, or several
/// - and each returned packet is resealed.
fn replace_filedescs(dir: &Path, edit: impl Fn(&str, &[u8]) -> Vec<Vec<u8>>) {
    for name in par2_files(dir) {
        let path = dir.join(&name);
        let bytes = std::fs::read(&path).expect("read par2");
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0usize;
        while i < bytes.len() {
            let framed = i + 64 <= bytes.len() && &bytes[i..i + 8] == MAGIC;
            let len = if framed {
                u64::from_le_bytes(bytes[i + 8..i + 16].try_into().unwrap()) as usize
            } else {
                0
            };
            if !framed || len < 64 || i + len > bytes.len() {
                out.push(bytes[i]);
                i += 1;
                continue;
            }
            let pkt = &bytes[i..i + len];
            i += len;
            if &pkt[48..64] != TYPE_FILEDESC {
                out.extend_from_slice(pkt);
                continue;
            }
            let member = String::from_utf8_lossy(&pkt[64 + 56..])
                .trim_end_matches('\0')
                .to_string();
            for mut p in edit(&member, pkt) {
                let seal = Md5::digest(&p[32..]);
                p[16..32].copy_from_slice(&seal);
                out.extend_from_slice(&p);
            }
        }
        std::fs::write(&path, out).expect("write par2");
    }
}

/// A1, the headline: one member's FileDesc is gone from every file of
/// the set, so the parse describes two of three. The verify must say so
/// in the repair's sentence and exit 6, never "All files are correct",
/// and `-p` must leave the recovery files where they are.
#[test]
fn a_member_with_no_filedesc_is_never_all_correct() {
    let dir = scratch("sweep-vr-a1");
    for (n, s) in [("a.bin", 1u32), ("b.bin", 2), ("c.bin", 3)] {
        write(&dir, n, &payload(20_000, s));
    }
    create(&dir, &["-c4", "set.par2", "a.bin", "b.bin", "c.bin"]);
    rewrite_filedescs(&dir, |member, _| member != "b.bin");
    let before = par2_files(&dir);

    let (code, text) = parfast(&dir, &["v", "set.par2"]);
    assert_eq!(code, 6, "{text}");
    assert!(
        text.contains("No details available for recoverable file number"),
        "{text}"
    );
    assert!(text.contains("Recovery will not be possible."), "{text}");
    assert!(!text.contains("All files are correct"), "{text}");
    assert!(
        text.contains("There are 3 recoverable files"),
        "the summary counts what the Main packet declares:\n{text}"
    );

    let (code, text) = parfast(&dir, &["v", "-p", "set.par2"]);
    assert_eq!(code, 6, "{text}");
    assert_eq!(
        par2_files(&dir),
        before,
        "-p purged a set it never verified"
    );

    // Repair refuses the same set, and purges nothing either.
    let (code, text) = parfast(&dir, &["r", "-p", "set.par2"]);
    assert_ne!(code, 0, "{text}");
    assert!(
        text.contains("No details available for recoverable file number"),
        "{text}"
    );
    assert_eq!(par2_files(&dir), before, "repair -p purged the set");
}

/// A1's extreme: a ONE-member set whose only FileDesc is gone, which
/// left `files` empty and verified nothing at all before saying so.
#[test]
fn a_one_member_set_with_no_filedesc_verifies_nothing_and_says_so() {
    let dir = scratch("sweep-vr-a1-one");
    write(&dir, "only.bin", &payload(20_000, 7));
    create(&dir, &["-c4", "set.par2", "only.bin"]);
    rewrite_filedescs(&dir, |_, _| false);

    let (code, text) = parfast(&dir, &["v", "-q", "set.par2"]);
    assert_eq!(code, 6, "{text}");
    assert!(!text.contains("All files are correct"), "{text}");
    assert!(
        text.contains("No details available for recoverable file number 1."),
        "{text}"
    );
}

/// A11: `-B` is the set's own directory, spelt absolutely while the set
/// argument is relative - SABnzbd's own shape. One directory, so the
/// repair runs.
#[test]
fn b_naming_the_sets_own_directory_another_way_repairs() {
    let dir = scratch("sweep-vr-a11");
    let member = payload(60_000, 0x9e37);
    write(&dir, "data.bin", &member);
    create(&dir, &["-c8", "set.par2", "data.bin"]);
    damage(&dir, "data.bin", 1_000, 3_000);

    let abs = std::fs::canonicalize(&*dir).expect("canonical");
    let abs = abs.to_str().expect("utf-8 scratch path");
    let (code, text) = parfast(&dir, &["r", "-B", abs, "set.par2"]);
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("Repair complete."), "{text}");
    assert_eq!(std::fs::read(dir.join("data.bin")).unwrap(), member);
}

/// A12: the index typed in one case, its volumes written in another.
/// The volumes must be loaded, or the repair has no recovery blocks.
#[test]
fn volumes_spelt_in_another_case_are_still_the_sets() {
    let dir = scratch("sweep-vr-a12");
    let member = payload(60_000, 0x51);
    write(&dir, "data.bin", &member);
    create(&dir, &["-c8", "-n2", "Movie.par2", "data.bin"]);
    // A case-only rename, which every volume this runs on allows.
    std::fs::rename(dir.join("Movie.par2"), dir.join("movie.par2")).expect("rename");
    assert!(
        par2_files(&dir).iter().any(|n| n.starts_with("Movie.vol")),
        "expected volumes spelt Movie.vol*: {:?}",
        par2_files(&dir)
    );
    damage(&dir, "data.bin", 2_000, 3_000);

    let (code, text) = parfast(&dir, &["r", "movie.par2"]);
    assert_eq!(code, 0, "{text}");
    assert_eq!(std::fs::read(dir.join("data.bin")).unwrap(), member);
}

/// A13: the member is gone from the set's directory and whole in a donor
/// directory named on the command line. Far more blocks are owed than
/// the set has parity for, so the count alone says "not possible" - but
/// the engine adopts the member and repairs.
#[test]
fn a_donor_on_the_command_line_is_asked_before_not_possible() {
    let root = scratch("sweep-vr-a13");
    let set = root.join("set");
    let backup = root.join("backup");
    std::fs::create_dir_all(&set).unwrap();
    std::fs::create_dir_all(&backup).unwrap();
    let member = payload(60_000, 0x77);
    write(&set, "data.bin", &member);
    create(&set, &["-c2", "set.par2", "data.bin"]);
    std::fs::rename(set.join("data.bin"), backup.join("a1b2c3d4")).expect("move");

    // The control: with no donor this IS hopeless, and says so.
    let (code, text) = parfast(&set, &["r", "set.par2"]);
    assert_eq!(code, 2, "{text}");
    assert!(text.contains("Repair is not possible."), "{text}");

    let (code, text) = parfast(&set, &["r", "set.par2", "../backup"]);
    assert_eq!(code, 0, "{text}");
    assert_eq!(std::fs::read(set.join("data.bin")).unwrap(), member);
}

/// A19, the member ON DISK: its FileDesc claims an absurd length, which
/// sized a bitmap in the verify's own accounting (`proven_bits`) before
/// the engine's scan ever ran.
#[test]
fn a_crafted_length_beside_a_real_file_does_not_abort_the_verify() {
    crafted_length("sweep-vr-a19-present", true);
}

/// A19, the member MISSING: the verify's accounting allocates nothing
/// for it, so this reaches the engine's `scan_members_for_blocks`,
/// which sized one bitmap per member from the declared length.
#[test]
fn a_crafted_length_on_a_missing_member_does_not_abort_the_verify() {
    crafted_length("sweep-vr-a19-missing", false);
}

fn crafted_length(tag: &str, keep_member: bool) {
    let dir = scratch(tag);
    write(&dir, "a.bin", &payload(20_000, 5));
    write(&dir, "b.bin", &payload(20_000, 6));
    create(&dir, &["-c4", "set.par2", "a.bin", "b.bin"]);
    rewrite_filedescs(&dir, |member, pkt| {
        if member == "a.bin" {
            pkt[64 + 48..64 + 56].copy_from_slice(&(u64::MAX / 2).to_le_bytes());
        }
        true
    });
    // The other member is damaged so the rolling scan has a reason to
    // run at all: a clean neighbour lets it return before building.
    damage(&dir, "b.bin", 100, 3_000);
    if !keep_member {
        std::fs::remove_file(dir.join("a.bin")).unwrap();
    }

    let (code, text) = parfast(&dir, &["v", "set.par2"]);
    assert!(
        (1..=8).contains(&code),
        "a crafted length must end in a dialect verdict, got {code}:\n{text}"
    );
    assert!(!text.contains("All files are correct"), "{text}");
}

/// A22: a repair the engine cannot finish. The damage outruns the
/// parity, and an unrelated file in the directory keeps the gate open so
/// the engine is asked (and the backup copy started). Its verdict is
/// Unrepairable, it wrote nothing, and it must leave no `data.bin.1`.
#[test]
fn an_unrepairable_verdict_leaves_no_backup_copy() {
    let dir = scratch("sweep-vr-a22");
    write(&dir, "data.bin", &noise(60_000, 0x31));
    create(&dir, &["-c2", "set.par2", "data.bin"]);
    write(&dir, "unrelated.txt", b"nothing of this set's in here");
    damage(&dir, "data.bin", 0, 30_000);

    let (code, text) = parfast(&dir, &["r", "set.par2"]);
    assert_eq!(code, 2, "{text}");
    assert!(text.contains("Repair is not possible."), "{text}");
    assert!(
        !dir.join("data.bin.1").exists(),
        "an Unrepairable run kept a backup of an untouched original:\n{text}"
    );
}

/// Section B, `-O`: a zero-length member's MD5 is the MD5 of every
/// empty file, so the first empty stray in the directory was renamed
/// onto it. An empty file proves nothing; the stray stays put.
#[test]
fn rename_only_does_not_take_an_empty_stray_for_an_empty_member() {
    let dir = scratch("sweep-vr-b-empty");
    write(&dir, "a.bin", &payload(20_000, 9));
    write(&dir, "empty.bin", &payload(4_000, 10));
    // `c` leaves an empty source out of the set, so the zero-length
    // member is made by surgery: its FileDesc rewritten to length 0 and
    // the MD5 of nothing, which is what a producer that keeps empty
    // members writes.
    create(&dir, &["-c2", "set.par2", "a.bin", "empty.bin"]);
    let nothing = Md5::digest(b"");
    rewrite_filedescs(&dir, |member, pkt| {
        if member == "empty.bin" {
            pkt[64 + 16..64 + 32].copy_from_slice(&nothing);
            pkt[64 + 32..64 + 48].copy_from_slice(&nothing);
            pkt[64 + 48..64 + 56].copy_from_slice(&0u64.to_le_bytes());
        }
        true
    });
    std::fs::remove_file(dir.join("empty.bin")).unwrap();
    write(&dir, "stray.log", b"");
    let (_, listed) = parfast(&dir, &["v", "set.par2"]);
    assert!(
        listed.contains("Target: \"empty.bin\" - missing."),
        "the surgery did not leave a missing zero-length member:\n{listed}"
    );

    let (_, text) = parfast(&dir, &["r", "-O", "set.par2"]);
    assert!(
        dir.join("stray.log").exists(),
        "-O renamed an unrelated empty file onto the empty member:\n{text}"
    );
}

/// The parse half of A1, read directly: two FileDescs for one member
/// that agree on the name, the length and the 16 KiB hash (so both bind
/// the file id) and disagree about the whole-file MD5. Both are evidence,
/// so they annihilate - and the id they leave behind must be RECORDED in
/// `undescribed`, at its position in the Main packet's list, not dropped.
#[test]
fn two_contradicting_filedescs_leave_their_id_in_undescribed() {
    let dir = scratch("sweep-vr-a1-annihilate");
    for (n, s) in [("a.bin", 1u32), ("b.bin", 2)] {
        write(&dir, n, &payload(20_000, s));
    }
    create(&dir, &["-c2", "set.par2", "a.bin", "b.bin"]);
    let fid_of_b = std::cell::Cell::new([0u8; 16]);
    replace_filedescs(&dir, |member, pkt| {
        if member != "b.bin" {
            return vec![pkt.to_vec()];
        }
        fid_of_b.set(pkt[64..80].try_into().unwrap());
        let mut twin = pkt.to_vec();
        twin[64 + 16] ^= 0xff;
        vec![pkt.to_vec(), twin]
    });

    let blobs: Vec<Vec<u8>> = par2_files(&dir)
        .iter()
        .map(|n| std::fs::read(dir.join(n)).unwrap())
        .collect();
    let refs: Vec<&[u8]> = blobs.iter().map(Vec::as_slice).collect();
    let set = nzbkit::par2::Par2Set::parse(&refs).expect("the set still parses");
    let names: Vec<&str> = set.files.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["a.bin"], "the contradicted member must not resolve");
    assert_eq!(set.undescribed.len(), 1, "{:?}", set.undescribed);
    assert_eq!(set.undescribed[0].1, fid_of_b.get());
    // Its POSITION in the Main packet's recovery list, read off the
    // packet itself rather than assumed from any sort order.
    let main = blobs[0]
        .windows(16)
        .position(|w| w == b"PAR 2.0\0Main\0\0\0\0")
        .expect("a Main packet")
        - 48;
    let body = &blobs[0][main + 64..];
    let n = u32::from_le_bytes(body[8..12].try_into().unwrap()) as usize;
    let at = (0..n)
        .position(|k| body[12 + 16 * k..28 + 16 * k] == fid_of_b.get())
        .expect("b.bin's id is in the Main packet");
    assert_eq!(set.undescribed[0].0, at);
}

/// Section B, `-O` on a case-insensitive volume: `Movie.bin` is on disk
/// as `movie.bin`, which the directory walk lists as unclaimed, and the
/// missing `copy.bin` has the same bytes. Renaming that file would move
/// the only copy of `Movie.bin` onto `copy.bin`. Skipped on a
/// case-sensitive volume, where `movie.bin` is a different file.
#[test]
fn rename_only_never_moves_a_members_own_case_alias() {
    let dir = scratch("sweep-vr-b-alias");
    let bytes = payload(20_000, 0x44);
    write(&dir, "Movie.bin", &bytes);
    write(&dir, "copy.bin", &bytes);
    if !dir.join("MOVIE.BIN").exists() {
        return;
    }
    create(&dir, &["-c2", "set.par2", "Movie.bin", "copy.bin"]);
    std::fs::remove_file(dir.join("copy.bin")).unwrap();
    std::fs::rename(dir.join("Movie.bin"), dir.join("movie.bin")).unwrap();

    let (_, text) = parfast(&dir, &["r", "-O", "set.par2"]);
    assert!(
        dir.join("Movie.bin").exists(),
        "-O moved a member's own file onto another member:\n{text}"
    );
}

/// A22 at the HANDSHAKE: a caller that refuses the repair after the
/// survey (a GUI Cancel) is answered "repair possible", and the backup
/// copy `announce` had already started is joined and removed - the
/// original was never touched, so `data.bin.1` would be a duplicate no
/// list records.
#[test]
fn a_refusal_at_the_handshake_leaves_no_backup_copy() {
    struct Refuse;
    impl parfast::repair::RepairWatch for Refuse {
        fn before_fold(&self, _survey: &parfast::verify::Survey) -> bool {
            false
        }
    }
    // `repair::run_watched` touches the engine's process globals the way
    // `run_with` does, so it takes the same lock.
    let _guard = crate::inproc::in_process();
    let dir = scratch("sweep-vr-a22-refuse");
    write(&dir, "data.bin", &noise(60_000, 0x52));
    create(&dir, &["-c8", "set.par2", "data.bin"]);
    damage(&dir, "data.bin", 1_000, 2_000);

    let opts = parfast::cli::Options {
        par2: Some(dir.join("set.par2")),
        ..Default::default()
    };
    let mut sink = parfast::out::Sink::buffered();
    let code = parfast::repair::run_watched(&opts, &mut sink, &Refuse);
    let (out, err) = sink.take();
    assert_eq!(code, 1, "{out}{err}");
    assert!(
        !dir.join("data.bin.1").exists(),
        "a refused repair kept a backup of an untouched original:\n{out}{err}"
    );
}

/// The backup slot is CLAIMED, not probed: a dangling symlink at
/// `data.bin.1` reads as absent to `exists()`, and the old copy then
/// followed it, creating a file wherever it pointed and putting `.1` on
/// the list `-p` deletes from. The slot must be skipped as occupied.
#[cfg(unix)]
#[test]
fn a_dangling_symlink_at_the_backup_slot_is_never_written_through() {
    let dir = scratch("sweep-vr-a22-symlink");
    write(&dir, "data.bin", &noise(60_000, 0x61));
    create(&dir, &["-c8", "set.par2", "data.bin"]);
    damage(&dir, "data.bin", 1_000, 2_000);
    let target = dir.join("elsewhere.bin");
    std::os::unix::fs::symlink(&target, dir.join("data.bin.1")).unwrap();

    let (code, text) = parfast(&dir, &["r", "set.par2"]);
    assert_eq!(code, 0, "{text}");
    assert!(
        !target.exists(),
        "the backup was written through the symlink:\n{text}"
    );
    assert!(
        std::fs::symlink_metadata(dir.join("data.bin.1"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(
        dir.join("data.bin.2").exists(),
        "no backup at the next slot"
    );
}
