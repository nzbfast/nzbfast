//! RAR 3.x `.rev` restore (Weaver parity item 8).
//!
//! The anchor is a REAL recovery set: `rev_newstyle.part{1..4}.rar` plus
//! `rev_newstyle.part{1,2}.rev` under the vendored engine's fixtures, a
//! RAR 4 volume set whose `.rev` files were written by a RAR tool and not
//! by anything in this repo. Sets with more recovery rows than that one
//! carries are built by [`rev3_file`], a GF(2^8) encoder in this module
//! that [`the_encoder_reproduces_the_rar_written_rev_files`] holds byte for
//! byte to the two real files first, so a synthetic `.rev` is the same
//! thing a RAR tool writes.

use super::*;
use crate::testscratch::ScratchDir;
use crate::unpack::{NestOutcome, extract_one_level};

const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vendor/rars/tests/fixtures/rar15_40/rar300"
);
const MEMBER: &str = "tmp/rars-rar4-rev-gen/payload.bin";
/// A budget no test set gets near, so only the tests that mean to move
/// the window do.
const ROOMY: u64 = 64 << 20;

fn scratch(tag: &str) -> ScratchDir {
    ScratchDir::attach(&std::env::temp_dir().join(format!(
        "nzbfast-rev3-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    )))
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(Path::new(FIXTURES).join(name)).unwrap()
}

fn volume_name(slot: usize) -> String {
    format!("rev_newstyle.part{}.rar", slot + 1)
}

fn volumes() -> Vec<Vec<u8>> {
    (0..4).map(|slot| fixture(&volume_name(slot))).collect()
}

/// The four data volumes and the two RAR-written `.rev` files.
fn real_set(dir: &Path) -> Vec<Vec<u8>> {
    let vols = volumes();
    for (slot, bytes) in vols.iter().enumerate() {
        std::fs::write(dir.join(volume_name(slot)), bytes).unwrap();
    }
    for n in 1..=2 {
        let name = format!("rev_newstyle.part{n}.rev");
        std::fs::write(dir.join(&name), fixture(&name)).unwrap();
    }
    vols
}

/// Every file in `dir` with its bytes.
fn snapshot(dir: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| {
            (
                e.file_name().to_string_lossy().into_owned(),
                std::fs::read(e.path()).unwrap(),
            )
        })
        .collect()
}

// ------------------------------------------------- a test-side encoder

fn gf_tables() -> ([u8; 512], [u8; 256]) {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let mut v: u16 = 1;
    for (i, slot) in exp.iter_mut().enumerate().take(255) {
        *slot = v as u8;
        log[v as usize] = i as u8;
        v <<= 1;
        if v > 0xff {
            v ^= 0x11d;
        }
    }
    for i in 255..512 {
        exp[i] = exp[i - 255];
    }
    (exp, log)
}

/// The `m` parity rows of `data` over its first `len` columns: a
/// systematic Reed-Solomon code over GF(2^8) whose generator has the roots
/// `a^1 ..= a^m`, the code `reconstruct_data_volumes` solves.
fn parity_rows(data: &[Vec<u8>], m: usize, len: usize) -> Vec<Vec<u8>> {
    let (exp, log) = gf_tables();
    let mul = |a: u8, b: u8| -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            exp[usize::from(log[usize::from(a)]) + usize::from(log[usize::from(b)])]
        }
    };
    // generator = prod (x + a^i), lowest power first, monic term dropped.
    let mut generator = vec![0u8; m];
    generator[0] = 1;
    let mut full = vec![1u8];
    for i in 1..=m {
        let root = exp[i];
        let mut next = vec![0u8; full.len() + 1];
        for (j, &c) in full.iter().enumerate() {
            next[j] ^= mul(c, root);
            next[j + 1] ^= c;
        }
        full = next;
    }
    generator.copy_from_slice(&full[..m]);
    let mut rows = vec![vec![0u8; len]; m];
    let mut shift = vec![0u8; m];
    for column in 0..len {
        shift.iter_mut().for_each(|s| *s = 0);
        for volume in data {
            let symbol = volume.get(column).copied().unwrap_or(0);
            let feedback = symbol ^ shift[m - 1];
            for j in (1..m).rev() {
                shift[j] = shift[j - 1] ^ mul(generator[j], feedback);
            }
            shift[0] = mul(generator[0], feedback);
        }
        for (row, out) in rows.iter_mut().enumerate() {
            out[column] = shift[m - 1 - row];
        }
    }
    rows
}

/// A whole RAR 3.x `.rev` file for row `row` of an `m`-row set over `data`:
/// the payload, then the trailer the module note describes.
fn rev3_file(data: &[Vec<u8>], m: usize, row: usize) -> Vec<u8> {
    let longest = data.iter().map(Vec::len).max().unwrap();
    let payload = longest - TRAILER_LEN as usize;
    let mut out = parity_rows(data, m, payload).swap_remove(row);
    out.extend_from_slice(&[(data.len() - 1) as u8, (m - 1) as u8, row as u8]);
    let crc = crc32fast::hash(&out);
    out.extend_from_slice(&crc.to_le_bytes());
    out
}

// --------------------------------------------------------------- tests

/// Proves the module's format reading on the real files: the trailer
/// parses to 4 data volumes, 2 rows and the right row each, and the
/// test encoder rebuilds both files byte for byte - payload AND trailer -
/// from the four volumes alone. Every synthetic `.rev` below rests on this.
#[test]
fn the_encoder_reproduces_the_rar_written_rev_files() {
    let vols = volumes();
    for row in 0..2 {
        let real = fixture(&format!("rev_newstyle.part{}.rev", row + 1));
        let trailer = read_rev3_trailer(&rars::recovery::stream::MemorySource(real.clone()))
            .expect("a RAR-written .rev parses");
        assert_eq!(
            trailer,
            Rev3Trailer {
                data_count: 4,
                recovery_count: 2,
                row,
                len: 2048
            }
        );
        assert_eq!(rev3_file(&vols, 2, row), real, "row {row}");
    }
}

/// A file with no trailer, or one whose CRC is off by one bit, is not a
/// `.rev`; neither is a RAR volume.
#[test]
fn only_a_self_consistent_trailer_reads_as_a_rev() {
    let mut real = fixture("rev_newstyle.part1.rev");
    real[100] ^= 1;
    assert_eq!(
        read_rev3_trailer(&rars::recovery::stream::MemorySource(real)),
        None
    );
    assert_eq!(
        read_rev3_trailer(&rars::recovery::stream::MemorySource(fixture(
            "rev_newstyle.part1.rar"
        ))),
        None
    );
}

/// Every RAR-written volume proves itself from its end block, at the
/// volume number it carries; one flipped data byte makes it Damaged.
#[test]
fn a_volume_proves_itself_from_its_end_block() {
    let dir = scratch("check");
    let vols = real_set(&dir);
    for (slot, bytes) in vols.iter().enumerate() {
        assert_eq!(
            check_volume(&dir.join(volume_name(slot))),
            VolumeCheck::Intact {
                slot: Some(slot),
                len: bytes.len() as u64,
                end: bytes.len() as u64,
            }
        );
    }
    let mut bad = vols[1].clone();
    bad[500] ^= 0x40;
    std::fs::write(dir.join(volume_name(1)), bad).unwrap();
    assert_eq!(
        check_volume(&dir.join(volume_name(1))),
        VolumeCheck::Damaged
    );
}

/// THE CASE: a volume gone, no PAR2 in the folder, so only the `.rev` can
/// save the set. Through the ladder's own rung (`try_rev_reconstruct`),
/// the rebuild is byte-identical to the original, and the set then
/// extracts byte-exact against an extraction of the untouched set.
#[test]
fn a_deleted_volume_is_rebuilt_from_the_rar_written_rev_and_extracts_byte_exact() {
    let intact = scratch("intact");
    real_set(&intact);
    assert_eq!(
        extract_one_level(&intact, None, 0).unwrap(),
        Some(NestOutcome::Produced)
    );
    let expected = std::fs::read(intact.join(MEMBER)).unwrap();
    assert_eq!(expected.len(), 6000);

    let dir = scratch("rebuild");
    let vols = real_set(&dir);
    std::fs::remove_file(dir.join(volume_name(1))).unwrap();

    assert!(super::super::try_rev_reconstruct(&dir));
    assert_eq!(std::fs::read(dir.join(volume_name(1))).unwrap(), vols[1]);
    assert!(
        !snapshot(&dir).keys().any(|n| n.starts_with("revtmp")),
        "no staging temp survives"
    );
    assert_eq!(
        extract_one_level(&dir, None, 0).unwrap(),
        Some(NestOutcome::Produced)
    );
    assert_eq!(std::fs::read(dir.join(MEMBER)).unwrap(), expected);
}

/// The set's short last volume: the solve pads it to a full shard, and the
/// rebuild must come back at its own 296 bytes, not 2048.
#[test]
fn the_short_last_volume_is_rebuilt_at_its_own_length() {
    let dir = scratch("short");
    let vols = real_set(&dir);
    std::fs::remove_file(dir.join(volume_name(3))).unwrap();
    assert!(try_rev3_reconstruct(&dir, ROOMY));
    assert_eq!(std::fs::read(dir.join(volume_name(3))).unwrap(), vols[3]);
    assert_eq!(vols[3].len(), 296);
}

/// A damaged volume is replaced in place and every good one is left
/// byte-for-byte alone - two at once, a damaged one and a deleted one,
/// using both rows.
#[test]
fn a_damaged_volume_is_replaced_and_the_good_ones_are_never_touched() {
    let dir = scratch("damaged");
    let vols = real_set(&dir);
    let mut bad = vols[2].clone();
    bad[1000] ^= 0xff;
    std::fs::write(dir.join(volume_name(2)), bad).unwrap();
    std::fs::remove_file(dir.join(volume_name(0))).unwrap();
    let mtime = |slot: usize| {
        std::fs::metadata(dir.join(volume_name(slot)))
            .unwrap()
            .modified()
            .unwrap()
    };
    let before = (mtime(1), mtime(3));

    assert!(try_rev3_reconstruct(&dir, ROOMY));

    for (slot, bytes) in vols.iter().enumerate() {
        assert_eq!(
            &std::fs::read(dir.join(volume_name(slot))).unwrap(),
            bytes,
            "slot {slot}"
        );
    }
    assert_eq!((mtime(1), mtime(3)), before, "intact volumes untouched");
}

/// Nothing missing, nothing damaged: the rung reports nothing and the
/// folder is exactly as it was.
#[test]
fn an_undamaged_set_does_not_touch_the_rev() {
    let dir = scratch("whole");
    real_set(&dir);
    let before = snapshot(&dir);
    assert!(!super::super::try_rev_reconstruct(&dir));
    assert_eq!(snapshot(&dir), before);
}

/// Three volumes gone against two rows: refused, and the folder is left
/// exactly as it was (no temp, no partial rebuild).
#[test]
fn damage_past_the_rev_count_fails_cleanly() {
    let dir = scratch("toomany");
    real_set(&dir);
    for slot in 0..3 {
        std::fs::remove_file(dir.join(volume_name(slot))).unwrap();
    }
    let before = snapshot(&dir);
    assert!(!try_rev3_reconstruct(&dir, ROOMY));
    assert_eq!(snapshot(&dir), before);

    // And the same refusal when the excess is DAMAGE rather than absence.
    let dir = scratch("toomany-damaged");
    let vols = real_set(&dir);
    for slot in 0..3 {
        let mut bad = vols[slot].clone();
        bad[600] ^= 1;
        std::fs::write(dir.join(volume_name(slot)), bad).unwrap();
    }
    let before = snapshot(&dir);
    assert!(!try_rev3_reconstruct(&dir, ROOMY));
    assert_eq!(snapshot(&dir), before);
}

/// Obfuscated recovery files - random names, no extension - are found by
/// content alone.
#[test]
fn obfuscated_rev_names_are_found_by_content() {
    let dir = scratch("obfuscated");
    let vols = real_set(&dir);
    std::fs::rename(dir.join("rev_newstyle.part1.rev"), dir.join("a8f3c1d09e")).unwrap();
    std::fs::rename(dir.join("rev_newstyle.part2.rev"), dir.join("77b2e4")).unwrap();
    std::fs::remove_file(dir.join(volume_name(2))).unwrap();
    assert!(try_rev3_reconstruct(&dir, ROOMY));
    assert_eq!(std::fs::read(dir.join(volume_name(2))).unwrap(), vols[2]);
}

/// A `.rev` that fails its own checksum is not used: with the other row
/// still good one volume is rebuilt; with both bad, nothing is.
#[test]
fn a_rev_failing_its_own_checksum_is_ignored() {
    let dir = scratch("badrev");
    let vols = real_set(&dir);
    let mut rev = fixture("rev_newstyle.part1.rev");
    rev[10] ^= 0x10;
    std::fs::write(dir.join("rev_newstyle.part1.rev"), &rev).unwrap();
    std::fs::remove_file(dir.join(volume_name(1))).unwrap();
    assert!(try_rev3_reconstruct(&dir, ROOMY));
    assert_eq!(std::fs::read(dir.join(volume_name(1))).unwrap(), vols[1]);

    std::fs::remove_file(dir.join(volume_name(1))).unwrap();
    let mut rev2 = fixture("rev_newstyle.part2.rev");
    rev2[10] ^= 0x10;
    std::fs::write(dir.join("rev_newstyle.part2.rev"), &rev2).unwrap();
    let before = snapshot(&dir);
    assert!(!try_rev3_reconstruct(&dir, ROOMY));
    assert_eq!(snapshot(&dir), before);
}

/// Three synthetic rows over the real volumes, two volumes lost, solved
/// across many windows (a 100-byte floor on a 2041-byte payload) and with
/// only one of the three rows needed spare: the windowed solve is the same
/// answer as a whole-volume one.
#[test]
fn a_windowed_solve_rebuilds_two_volumes_from_three_rows() {
    let dir = scratch("windows");
    let vols = volumes();
    for (slot, bytes) in vols.iter().enumerate() {
        std::fs::write(dir.join(volume_name(slot)), bytes).unwrap();
    }
    for row in 0..3 {
        std::fs::write(
            dir.join(format!("rev_newstyle.part{}.rev", row + 1)),
            rev3_file(&vols, 3, row),
        )
        .unwrap();
    }
    std::fs::remove_file(dir.join(volume_name(0))).unwrap();
    std::fs::remove_file(dir.join(volume_name(2))).unwrap();
    // (2 * 4 + 3) shards x 100 bytes fits a 1,100-byte budget exactly.
    assert!(try_rev3_reconstruct_in(&dir, 1_100, 100));
    for (slot, bytes) in vols.iter().enumerate() {
        assert_eq!(
            &std::fs::read(dir.join(volume_name(slot))).unwrap(),
            bytes,
            "slot {slot}"
        );
    }
}

/// A set too wide for the budget at the window floor is refused rather
/// than solved in slivers, and the folder is untouched.
#[test]
fn a_set_over_the_budget_is_refused() {
    assert_eq!(rev3_window(1_099, 4, 3, 2041, 100), None);
    assert_eq!(rev3_window(1_100, 4, 3, 2041, 100), Some(100));
    assert_eq!(rev3_window(u64::MAX, 4, 3, 2041, 100), Some(2041));
    let dir = scratch("budget");
    real_set(&dir);
    std::fs::remove_file(dir.join(volume_name(1))).unwrap();
    let before = snapshot(&dir);
    assert!(!try_rev3_reconstruct_in(&dir, 100, 100));
    assert_eq!(snapshot(&dir), before);
}

/// The slot a name implies, and the old-style name a slot derives.
#[test]
fn old_style_names_map_to_slots_and_back() {
    assert_eq!(name_slot("set.part1.rar"), Some(0));
    assert_eq!(name_slot("set.part12.rar"), Some(11));
    assert_eq!(name_slot("set.rar"), Some(0));
    assert_eq!(name_slot("set.r00"), Some(1));
    assert_eq!(name_slot("set.r09"), Some(10));
    assert_eq!(name_slot("set.001"), Some(0));
    assert_eq!(derive_old_name("set.rar", 0, 3).as_deref(), Some("set.r02"));
    assert_eq!(derive_old_name("set.r02", 3, 0).as_deref(), Some("set.rar"));
    assert_eq!(derive_old_name("SET.R02", 3, 1).as_deref(), Some("SET.R00"));
    assert_eq!(derive_old_name("set.r02", 2, 1), None, "wrong ordinal");
    assert_eq!(derive_old_name("set.rar", 0, 101), None, "past .r99");
}
