//! rev-volume recovery tests, moved out of rarfix.rs so the file
//! stays under the size-gate ceiling (pure code motion, gate recipe:
//! test code moves to a sibling module; mod name matches the file so
//! the gate classifies these fns as test code).

use super::*;
use rars::recovery::rar5::encode_parity_shards;
use std::path::Path;

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("nzbfast-rev-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Writes a synthetic RAR volume set plus its `.rev` recovery volumes
/// into `dir`, and returns the data volumes' bytes in slot order.
///
/// The "volumes" are opaque byte blobs: `try_rev_reconstruct` matches
/// them to REV slots by size and CRC32 alone and never parses them, so
/// real RAR framing would only slow the test down. `mangle_parity`
/// builds a `.rev` whose payload checksum is self-consistent but whose
/// parity is wrong, to exercise the verify-before-publish gate.
fn build_set(
    dir: &Path,
    sizes: &[usize],
    recovery_count: usize,
    mangle_parity: bool,
) -> Vec<Vec<u8>> {
    build_named_set(dir, "set", sizes, recovery_count, mangle_parity)
}

/// As `build_set`, under an explicit release name so a test can put two
/// independent sets in one directory.
fn build_named_set(
    dir: &Path,
    release: &str,
    sizes: &[usize],
    recovery_count: usize,
    mangle_parity: bool,
) -> Vec<Vec<u8>> {
    let data: Vec<Vec<u8>> = sizes
        .iter()
        .enumerate()
        .map(|(index, &len)| {
            (0..len)
                .map(|byte| (byte * 7 + index * 29 + 11) as u8)
                .collect()
        })
        .collect();
    for (index, volume) in data.iter().enumerate() {
        std::fs::write(
            dir.join(format!("{release}.part{:02}.rar", index + 1)),
            volume,
        )
        .unwrap();
    }

    let mut shard_len = *sizes.iter().max().unwrap();
    shard_len += shard_len & 1;
    let padded: Vec<Vec<u8>> = data
        .iter()
        .map(|volume| {
            let mut shard = vec![0u8; shard_len];
            shard[..volume.len()].copy_from_slice(volume);
            shard
        })
        .collect();
    let refs: Vec<&[u8]> = padded.iter().map(Vec::as_slice).collect();
    let mut parity = encode_parity_shards(&refs, recovery_count).unwrap();
    if mangle_parity {
        for row in &mut parity {
            row[0] ^= 0xff;
        }
    }

    let data_count = data.len() as u16;
    for row in 0..recovery_count {
        let payload = &parity[row];
        let mut body = Vec::new();
        body.push(1u8);
        body.extend_from_slice(&data_count.to_le_bytes());
        body.extend_from_slice(&(recovery_count as u16).to_le_bytes());
        body.extend_from_slice(&((data_count as usize + row) as u16).to_le_bytes());
        body.extend_from_slice(&crc32fast::hash(payload).to_le_bytes());
        for volume in &data {
            body.extend_from_slice(&(volume.len() as u64).to_le_bytes());
            body.extend_from_slice(&crc32fast::hash(volume).to_le_bytes());
        }
        let mut rev = Vec::new();
        rev.extend_from_slice(b"Rar!\x1aRev");
        rev.extend_from_slice(&[0u8; 4]);
        rev.extend_from_slice(&(body.len() as u32).to_le_bytes());
        rev.extend_from_slice(&body);
        let header_crc = crc32fast::hash(&rev[12..16 + body.len()]);
        rev[8..12].copy_from_slice(&header_crc.to_le_bytes());
        rev.extend_from_slice(payload);
        std::fs::write(dir.join(format!("{release}.part{:02}.rev", row + 1)), &rev).unwrap();
    }
    data
}

/// Every file in `dir` with its bytes, for asserting nothing moved.
fn snapshot(dir: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| {
            (
                e.file_name().to_string_lossy().into_owned(),
                std::fs::read(e.path()).unwrap(),
            )
        })
        .collect()
}

#[test]
fn rev_reconstruct_rebuilds_a_missing_volume_and_leaves_the_others_alone() {
    let dir = temp_dir("rebuild");
    let data = build_set(&dir, &[600, 512, 480, 640], 2, false);
    let gone = dir.join("set.part02.rar");
    std::fs::remove_file(&gone).unwrap();
    let before = snapshot(&dir);

    assert!(try_rev_reconstruct(&dir));

    assert_eq!(
        std::fs::read(&gone).unwrap(),
        data[1],
        "the rebuilt volume must be byte-exact"
    );
    for (name, bytes) in &before {
        assert_eq!(
            &std::fs::read(dir.join(name)).unwrap(),
            bytes,
            "{name} was modified by a repair that did not concern it"
        );
    }
    assert!(
        !snapshot(&dir).keys().any(|name| name.starts_with("revtmp")),
        "no staging temp may survive a successful repair"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rev_reconstruct_rebuilds_two_missing_volumes_from_two_recovery_volumes() {
    let dir = temp_dir("rebuild-two");
    let data = build_set(&dir, &[600, 512, 480, 640], 2, false);
    std::fs::remove_file(dir.join("set.part01.rar")).unwrap();
    std::fs::remove_file(dir.join("set.part04.rar")).unwrap();

    assert!(try_rev_reconstruct(&dir));

    assert_eq!(std::fs::read(dir.join("set.part01.rar")).unwrap(), data[0]);
    assert_eq!(std::fs::read(dir.join("set.part04.rar")).unwrap(), data[3]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rev_reconstruct_repairs_a_damaged_volume_in_place() {
    let dir = temp_dir("damaged");
    let data = build_set(&dir, &[600, 512, 480], 1, false);
    // Present but corrupt: it fails the slot's CRC, so its slot is
    // rebuilt and the bad file is replaced.
    let damaged = dir.join("set.part03.rar");
    let mut bytes = std::fs::read(&damaged).unwrap();
    bytes[10..60].fill(0x5a);
    std::fs::write(&damaged, &bytes).unwrap();

    assert!(try_rev_reconstruct(&dir));
    assert_eq!(std::fs::read(&damaged).unwrap(), data[2]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rev_reconstruct_leaves_everything_alone_when_there_is_too_much_damage() {
    let dir = temp_dir("too-much");
    build_set(&dir, &[600, 512, 480, 640], 1, false);
    // Two gone, one recovery volume: unrepairable arithmetic.
    std::fs::remove_file(dir.join("set.part01.rar")).unwrap();
    std::fs::remove_file(dir.join("set.part03.rar")).unwrap();
    let before = snapshot(&dir);

    assert!(!try_rev_reconstruct(&dir));

    assert_eq!(
        snapshot(&dir),
        before,
        "a refused repair must change nothing"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rev_reconstruct_publishes_nothing_when_a_rebuild_fails_its_checksum() {
    let dir = temp_dir("bad-parity");
    // The .rev's payload checksum is self-consistent, so it survives
    // every earlier gate - but the parity is wrong, so the rebuild it
    // produces cannot match the slot. Publishing that would replace a
    // known-missing volume with a silently wrong one.
    build_set(&dir, &[600, 512, 480], 1, true);
    std::fs::remove_file(dir.join("set.part02.rar")).unwrap();
    let before = snapshot(&dir);

    assert!(!try_rev_reconstruct(&dir));

    assert_eq!(
        snapshot(&dir),
        before,
        "nothing may be published or left behind"
    );
    assert!(!dir.join("set.part02.rar").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rev_reconstruct_ignores_a_corrupt_recovery_volume() {
    let dir = temp_dir("corrupt-rev");
    build_set(&dir, &[600, 512, 480], 1, false);
    std::fs::remove_file(dir.join("set.part02.rar")).unwrap();
    // Corrupt the .rev payload itself: it fails its own declared CRC and
    // must be dropped rather than solved against.
    let rev = dir.join("set.part01.rev");
    let mut bytes = std::fs::read(&rev).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    std::fs::write(&rev, &bytes).unwrap();
    let before = snapshot(&dir);

    assert!(!try_rev_reconstruct(&dir));
    assert_eq!(snapshot(&dir), before);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rev_reconstruct_repairs_every_independent_set_in_one_folder() {
    // Two unrelated releases' recovery volumes side by side, BOTH with a
    // volume missing. Grouping alone is not enough: stopping at the first
    // group that rebuilds something leaves the second release broken, its
    // extraction fails anyway, and the .rev files that could have saved it
    // are never consulted again.
    let dir = temp_dir("two-sets");
    // Different slot geometry, so the two sets cannot be confused.
    let alpha = build_named_set(&dir, "alpha", &[600, 512, 480], 1, false);
    let beta = build_named_set(&dir, "beta", &[300, 256, 240, 288], 1, false);
    std::fs::remove_file(dir.join("alpha.part02.rar")).unwrap();
    std::fs::remove_file(dir.join("beta.part03.rar")).unwrap();

    assert!(try_rev_reconstruct(&dir));

    assert_eq!(
        std::fs::read(dir.join("alpha.part02.rar")).unwrap(),
        alpha[1],
        "the first set was not rebuilt"
    );
    assert_eq!(
        std::fs::read(dir.join("beta.part03.rar")).unwrap(),
        beta[2],
        "the second set was skipped once the first succeeded"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rev_reconstruct_repairs_the_healthy_set_when_another_is_unrecoverable() {
    // One set beyond saving must not stop the other from being repaired.
    let dir = temp_dir("one-doomed");
    let alpha = build_named_set(&dir, "alpha", &[600, 512, 480], 1, false);
    build_named_set(&dir, "beta", &[300, 256, 240, 288], 1, false);
    std::fs::remove_file(dir.join("alpha.part02.rar")).unwrap();
    // Two gone from beta against a single recovery volume: unrepairable.
    std::fs::remove_file(dir.join("beta.part01.rar")).unwrap();
    std::fs::remove_file(dir.join("beta.part03.rar")).unwrap();

    assert!(try_rev_reconstruct(&dir));
    assert_eq!(
        std::fs::read(dir.join("alpha.part02.rar")).unwrap(),
        alpha[1]
    );
    assert!(!dir.join("beta.part01.rar").exists());
    assert!(!dir.join("beta.part03.rar").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rev_reconstruct_sweeps_temps_abandoned_by_an_earlier_crash() {
    // A crash between the verify and the renames leaves staging temps.
    // Old ones are abandoned by definition and get cleared; a fresh one
    // may belong to a repair running right now and must be left alone.
    let dir = temp_dir("stale-temps");
    build_set(&dir, &[600, 512, 480], 1, false);
    let stale = dir.join("revtmp999999-0-0");
    let fresh = dir.join("revtmp999998-0-0");
    std::fs::write(&stale, b"abandoned").unwrap();
    std::fs::write(&fresh, b"in flight").unwrap();
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(24 * 60 * 60);
    std::fs::File::options()
        .write(true)
        .open(&stale)
        .unwrap()
        .set_modified(old)
        .unwrap();

    // Nothing is missing, so this returns false - the sweep still runs.
    assert!(!try_rev_reconstruct(&dir));
    assert!(!stale.exists(), "an abandoned temp must be cleared");
    assert!(fresh.exists(), "a temp that may be in flight must be left");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rev_sweep_spares_a_stale_lookalike_that_is_not_ours() {
    // The sweep's delete is unconditional, so its predicate is the only
    // thing standing between it and the user's files. A prefix match is
    // not enough: `nzbfast extract <dir>` runs this over a directory of
    // arbitrary content, and a restored file carries the archive's own
    // mtime, which is commonly years old. Only the full staging grammar
    // - revtmp<pid>-<slot>-<n>, all digits - is ours to delete.
    let dir = temp_dir("stale-lookalike");
    build_set(&dir, &[600, 512, 480], 1, false);
    let bystander = dir.join("revtmpMovie.mkv");
    let owned = dir.join(format!("revtmp{}-0-0", std::process::id()));
    std::fs::write(&bystander, b"the user's file").unwrap();
    std::fs::write(&owned, b"abandoned").unwrap();
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(24 * 60 * 60);
    for p in [&bystander, &owned] {
        std::fs::File::options()
            .write(true)
            .open(p)
            .unwrap()
            .set_modified(old)
            .unwrap();
    }

    // Nothing is missing, so this returns false - the sweep still runs.
    assert!(!try_rev_reconstruct(&dir));
    assert!(
        bystander.exists(),
        "a stale non-owned name must survive the sweep"
    );
    assert!(
        !owned.exists(),
        "an abandoned owned temp must still be cleared"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rev_reconstruct_does_nothing_when_the_set_is_already_whole() {
    let dir = temp_dir("whole");
    build_set(&dir, &[600, 512, 480], 1, false);
    let before = snapshot(&dir);

    assert!(!try_rev_reconstruct(&dir));
    assert_eq!(snapshot(&dir), before);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The neighbour's name is sliced at offsets found by a case-insensitive
/// search, so characters whose lowercase form is a different byte length
/// must not shift them. U+0130 (İ, 2 bytes) lowercases to 3 bytes and
/// U+1E9E (ẞ, 3 bytes) to 2, one shift in each direction; a `to_lowercase()`
/// copy would put `.part` at the wrong offset and panic or mangle the name.
#[test]
fn derived_part_names_survive_length_changing_case() {
    // "İstanbul" + "ẞ" - two chars whose lowercase byte length differs.
    for stem in [
        "\u{130}stanbul",
        "Gru\u{1e9e}e",
        "\u{130}\u{1e9e}x",
        "Plain",
    ] {
        let known = format!("{stem}.part03.rar");
        let got = derive_part_name(&known, 2, 6).expect("neighbour names its own slot");
        assert_eq!(got, format!("{stem}.part07.rar"));
        // The prefix must come out of the original string untouched.
        assert!(
            got.starts_with(stem),
            "{got} lost the original bytes of {stem}"
        );
    }

    // A length-changing char inside the extension side of the split too,
    // and mixed casing on `.part` itself, which is preserved.
    let known = "Se\u{130}t.PART002.r\u{130}r";
    assert_eq!(
        derive_part_name(known, 1, 11).unwrap(),
        "Se\u{130}t.PART012.r\u{130}r"
    );

    // A neighbour that does not number its own slot tells us nothing.
    assert!(derive_part_name("x.part03.rar", 0, 1).is_none());
    assert!(derive_part_name("x.rar", 0, 1).is_none());
    assert!(derive_part_name("\u{130}.part", 0, 1).is_none());
}
