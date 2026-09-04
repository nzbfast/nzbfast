//! The damaged-volume hint on the recovery-record rung (TODO §11 (b)):
//! what the hinted pass opens, what it leaves alone, and that a wrong
//! hint costs a second pass rather than the repair.

use super::rrhint::{
    DamageHint, RrPassStats, Verdict, rr_repair_volumes, try_rar_rr_repair_hinted,
};
use super::*;

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("nzbfast-rrhint-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn payload(n: u32, seed: u32) -> Vec<u8> {
    (0..n)
        .flat_map(|i| i.wrapping_mul(seed).to_le_bytes())
        .collect()
}

/// A compressed multivolume RAR5 set with a 20% recovery record in every
/// volume. Returns the volume paths in set order.
fn write_rr_set(dir: &std::path::Path, payload: &[u8]) -> Vec<PathBuf> {
    use rars::rar50::{CompressedEntry, Rar50VolumeWriter, WriterOptions};
    let entries = [CompressedEntry {
        name: b"inner/data.bin",
        data: payload,
        mtime: None,
        attributes: 0o100644,
        host_os: 1,
    }];
    let volumes = Rar50VolumeWriter::new(WriterOptions::default())
        .compressed_entries(&entries)
        .max_payload_per_volume(64 * 1024)
        .recovery_percent(Some(20))
        .finish()
        .unwrap();
    assert!(
        volumes.len() >= 4,
        "expected a multivolume set, got {}",
        volumes.len()
    );
    let mut paths = Vec::new();
    for (index, bytes) in volumes.iter().enumerate() {
        let p = dir.join(format!("set.part{:02}.rar", index + 1));
        std::fs::write(&p, bytes).unwrap();
        paths.push(p);
    }
    paths
}

/// Flip a run of bytes in the middle of one volume's payload - 1% of the
/// volume, so the short last volume stays inside its 20% record too.
fn damage(path: &std::path::Path) -> (u64, u64) {
    let mut bytes = std::fs::read(path).unwrap();
    let start = bytes.len() / 3;
    let end = start + (bytes.len() / 100).max(16);
    for b in &mut bytes[start..end] {
        *b ^= 0x5a;
    }
    std::fs::write(path, &bytes).unwrap();
    (start as u64, end as u64)
}

fn size(p: &std::path::Path) -> u64 {
    std::fs::metadata(p).unwrap().len()
}

/// The control every repair leg here opens with: the damage is REAL, so
/// a blind extraction of the set as it stands refuses it. `try_unrar`
/// stages, so a refusal leaves nothing on disk and the repair that
/// follows starts from the same place it would have.
///
/// Without this, a leg proves nothing on a fixture nothing checksums -
/// which is exactly what `Rar50VolumeWriter` built until 22 Aug 2026: a
/// split STORED member carried no CRC anywhere (and the compressed
/// writer stores an incompressible entry, which `payload()` is), so the
/// damaged bytes extracted as a success. Fixed in
/// `vendor/rars/src/rar50/write/volume.rs`; see vendor/rars/VENDORING.md.
/// Revert that row and every call below fails, which is the point of
/// calling it.
fn assert_the_fixture_is_really_damaged(dir: &std::path::Path) {
    assert!(
        !try_unrar(dir, None),
        "the fixture must actually be corrupt - a blind extraction of it \
         succeeded, so nothing this leg goes on to assert about the repair \
         means anything"
    );
    assert!(
        !dir.join("inner").exists(),
        "a refused extraction must leave nothing behind"
    );
}

#[cfg(unix)]
fn set_mode(p: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn hinted_pass_leaves_par2_proven_volumes_unread() {
    let dir = temp_dir("skip");
    let data = payload(100_000, 2246822519);
    let vols = write_rr_set(&dir, &data);
    let bad = 2usize;
    let range = damage(&vols[bad]);
    assert_the_fixture_is_really_damaged(&dir);

    let mut hint = DamageHint::default();
    for (i, v) in vols.iter().enumerate() {
        let ranges = if i == bad { vec![range] } else { Vec::new() };
        hint.insert(v.file_name().unwrap().to_str().unwrap(), size(v), ranges);
    }
    // Every intact volume is made unreadable: a pass that opened one
    // would fail it as a hard failure, so a clean pass is the proof
    // that nothing touched them - on top of the byte count.
    #[cfg(unix)]
    for (i, v) in vols.iter().enumerate() {
        if i != bad {
            set_mode(v, 0o000);
        }
    }
    let stats = rr_repair_volumes(&dir, &vols, None, Some(&hint));
    #[cfg(unix)]
    for (i, v) in vols.iter().enumerate() {
        if i != bad {
            set_mode(v, 0o644);
        }
    }
    let intact_bytes: u64 = vols
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != bad)
        .map(|(_, v)| size(v))
        .sum();
    assert_eq!(stats.hard_failures, 0, "{stats:?}");
    assert_eq!(stats.rewritten, 1, "{stats:?}");
    assert_eq!(stats.bytes_scanned, size(&vols[bad]), "{stats:?}");
    assert_eq!(stats.bytes_skipped, intact_bytes, "{stats:?}");
    assert_eq!(stats.skipped.len(), vols.len() - 1);
    assert!(!stats.skipped.contains(&vols[bad]));

    assert!(try_unrar(&dir, None));
    assert_eq!(
        std::fs::read(dir.join("inner").join("data.bin")).unwrap(),
        data
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn blind_pass_scans_every_volume_as_before() {
    let dir = temp_dir("blind");
    let data = payload(100_000, 374761393);
    let vols = write_rr_set(&dir, &data);
    damage(&vols[1]);
    assert_the_fixture_is_really_damaged(&dir);
    let total: u64 = vols.iter().map(|v| size(v)).sum();

    let stats = rr_repair_volumes(&dir, &vols, None, None);
    assert_eq!(stats.hard_failures, 0, "{stats:?}");
    // Only the damaged volume is rewritten - the intact ones open their
    // record, prove the prefix, and are counted separately.
    assert_eq!(stats.rewritten, 1, "{stats:?}");
    assert_eq!(stats.intact, vols.len() - 1, "{stats:?}");
    assert!(stats.skipped.is_empty());
    assert_eq!(stats.bytes_skipped, 0);
    assert_eq!(stats.bytes_scanned, total);

    // And the public entry point, which is the blind form.
    assert!(try_rar_rr_repair(&dir, None));
    assert_eq!(
        std::fs::read(dir.join("inner").join("data.bin")).unwrap(),
        data
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn volumes_outside_par2_coverage_get_the_full_pass() {
    let dir = temp_dir("partial");
    let data = payload(100_000, 2654435761);
    let vols = write_rr_set(&dir, &data);
    let n = vols.len();
    // PAR2 spoke for the first half only; the damage is in the second
    // half, where the hint knows nothing.
    let bad = n - 1;
    damage(&vols[bad]);
    assert_the_fixture_is_really_damaged(&dir);
    let mut hint = DamageHint::default();
    for v in &vols[..n / 2] {
        hint.insert(
            v.file_name().unwrap().to_str().unwrap(),
            size(v),
            Vec::new(),
        );
    }
    for v in &vols[n / 2..] {
        assert_eq!(hint.verdict(v), Verdict::Unknown);
    }

    let stats = rr_repair_volumes(&dir, &vols, None, Some(&hint));
    let covered: u64 = vols[..n / 2].iter().map(|v| size(v)).sum();
    let uncovered: u64 = vols[n / 2..].iter().map(|v| size(v)).sum();
    assert_eq!(stats.hard_failures, 0, "{stats:?}");
    assert_eq!(
        stats.rewritten + stats.intact,
        n - n / 2,
        "every uncovered volume opened: {stats:?}"
    );
    assert_eq!(stats.rewritten, 1, "{stats:?}");
    assert_eq!(stats.bytes_skipped, covered);
    assert_eq!(stats.bytes_scanned, uncovered);

    assert!(try_unrar(&dir, None));
    assert_eq!(
        std::fs::read(dir.join("inner").join("data.bin")).unwrap(),
        data
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_wrong_hint_costs_a_second_pass_not_the_repair() {
    let dir = temp_dir("wrong");
    let data = payload(100_000, 2246822519);
    let vols = write_rr_set(&dir, &data);
    damage(&vols[1]);
    assert_the_fixture_is_really_damaged(&dir);
    // The hint vouches for EVERY volume, the damaged one included.
    let mut hint = DamageHint::default();
    for v in &vols {
        hint.insert(
            v.file_name().unwrap().to_str().unwrap(),
            size(v),
            Vec::new(),
        );
    }
    assert!(try_rar_rr_repair_hinted(&dir, None, Some(&hint)));
    assert_eq!(
        std::fs::read(dir.join("inner").join("data.bin")).unwrap(),
        data
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn hinted_entry_point_repairs_and_extracts() {
    let dir = temp_dir("entry");
    let data = payload(100_000, 374761393);
    let vols = write_rr_set(&dir, &data);
    let range = damage(&vols[0]);
    assert_the_fixture_is_really_damaged(&dir);
    let mut hint = DamageHint::default();
    for (i, v) in vols.iter().enumerate() {
        let ranges = if i == 0 { vec![range] } else { Vec::new() };
        hint.insert(v.file_name().unwrap().to_str().unwrap(), size(v), ranges);
    }
    assert!(try_rar_rr_repair_hinted(&dir, None, Some(&hint)));
    assert_eq!(
        std::fs::read(dir.join("inner").join("data.bin")).unwrap(),
        data
    );
    assert!(
        !std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().contains("rrtmp")),
        "no repair temp may survive"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_length_mismatch_downgrades_a_named_volume_to_unknown() {
    let dir = temp_dir("length");
    let p = dir.join("set.rar");
    std::fs::write(&p, b"Rar!\x1a\x07\x01\x00 not really").unwrap();
    let mut hint = DamageHint::default();
    hint.insert("set.rar", size(&p) + 1, Vec::new());
    assert_eq!(hint.verdict(&p), Verdict::Unknown);
    hint.insert("set.rar", size(&p), Vec::new());
    assert_eq!(hint.verdict(&p), Verdict::Intact);
    hint.insert("set.rar", size(&p), vec![(0, 4)]);
    assert_eq!(hint.verdict(&p), Verdict::Damaged(vec![(0, 4)]));
    assert_eq!(hint.verdict(&dir.join("other.rar")), Verdict::Unknown);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn from_reports_maps_blocks_to_clipped_byte_ranges() {
    use nzbkit::live::SlotReport;
    let reports = vec![
        (
            0,
            SlotReport {
                par2_name: Some("a.part01.rar".into()),
                total_blocks: 3,
                bad_blocks: vec![0, 2],
                live_blocks: 3,
                readback_blocks: 0,
                length: 2_500,
                prefix_md5: None,
            },
        ),
        (
            1,
            SlotReport {
                par2_name: Some("a.part02.rar".into()),
                total_blocks: 3,
                bad_blocks: Vec::new(),
                live_blocks: 3,
                readback_blocks: 0,
                length: 3_000,
                prefix_md5: None,
            },
        ),
        (
            2,
            SlotReport {
                par2_name: Some("a.nfo".into()),
                total_blocks: 0,
                bad_blocks: vec![0],
                live_blocks: 0,
                readback_blocks: 1,
                length: 77,
                prefix_md5: None,
            },
        ),
        (
            3,
            SlotReport {
                par2_name: None,
                total_blocks: 0,
                bad_blocks: Vec::new(),
                live_blocks: 0,
                readback_blocks: 0,
                length: 0,
                prefix_md5: None,
            },
        ),
    ];
    let hint = DamageHint::from_reports(&reports, 1_000);
    let dir = temp_dir("reports");
    for (name, len) in [
        ("a.part01.rar", 2_500),
        ("a.part02.rar", 3_000),
        ("a.nfo", 77),
    ] {
        std::fs::write(dir.join(name), vec![0u8; len]).unwrap();
    }
    // Last block is short: clipped to the file length.
    assert_eq!(
        hint.verdict(&dir.join("a.part01.rar")),
        Verdict::Damaged(vec![(0, 1_000), (2_000, 2_500)])
    );
    assert_eq!(hint.verdict(&dir.join("a.part02.rar")), Verdict::Intact);
    // No IFSC, MD5 failed: the whole file.
    assert_eq!(
        hint.verdict(&dir.join("a.nfo")),
        Verdict::Damaged(vec![(0, 77)])
    );
    let _ = RrPassStats::default();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The measurement behind the TODO §11 (b) close note: blind pass vs
/// hinted pass over a 24 x 8 MiB stored RAR5 set with one damaged
/// volume. `cargo test --release -p nzbfast --bin nzbfast
/// rr_hint_wall_time -- --ignored --nocapture`.
#[test]
#[ignore]
fn rr_hint_wall_time() {
    use rars::rar50::{Rar50VolumeWriter, StoredEntry, WriterOptions};
    let dir = temp_dir("wall");
    let data = payload(24 * 2 * 1024 * 1024, 2654435761);
    let volumes = Rar50VolumeWriter::new(WriterOptions::default())
        .stored_entry(StoredEntry {
            name: b"inner/data.bin",
            data: &data,
            mtime: None,
            attributes: 0o100644,
            host_os: 1,
        })
        .max_payload_per_volume(8 * 1024 * 1024)
        .recovery_percent(Some(5))
        .finish()
        .unwrap();
    let mut vols = Vec::new();
    for (index, bytes) in volumes.iter().enumerate() {
        let p = dir.join(format!("set.part{:02}.rar", index + 1));
        std::fs::write(&p, bytes).unwrap();
        vols.push(p);
    }
    let pristine: Vec<Vec<u8>> = vols.iter().map(|v| std::fs::read(v).unwrap()).collect();
    let bad = vols.len() / 2;
    let restore = |vols: &[PathBuf]| {
        for (v, b) in vols.iter().zip(&pristine) {
            std::fs::write(v, b).unwrap();
        }
        let _ = std::fs::remove_dir_all(dir.join("inner"));
    };
    let mut hint = DamageHint::default();
    let mut range = (0, 0);
    for (i, v) in vols.iter().enumerate() {
        hint.insert(
            v.file_name().unwrap().to_str().unwrap(),
            size(v),
            Vec::new(),
        );
        if i == bad {
            range = damage(v);
        }
    }
    hint.insert(
        vols[bad].file_name().unwrap().to_str().unwrap(),
        size(&vols[bad]),
        vec![range],
    );
    let total: u64 = vols.iter().map(|v| size(v)).sum();
    eprintln!(
        "set: {} volumes, {:.1} MB, volume {} damaged",
        vols.len(),
        total as f64 / 1e6,
        bad + 1
    );
    for round in 0..3 {
        restore(&vols);
        damage(&vols[bad]);
        let t = std::time::Instant::now();
        assert!(try_rar_rr_repair(&dir, None));
        let blind = t.elapsed();
        restore(&vols);
        damage(&vols[bad]);
        let t = std::time::Instant::now();
        assert!(try_rar_rr_repair_hinted(&dir, None, Some(&hint)));
        let hinted = t.elapsed();
        assert_eq!(
            std::fs::read(dir.join("inner").join("data.bin")).unwrap(),
            data
        );
        // And the RR pass on its own, without the extraction both arms pay.
        restore(&vols);
        damage(&vols[bad]);
        let t = std::time::Instant::now();
        let blind_pass = rr_repair_volumes(&dir, &vols, None, None);
        let pass_blind = t.elapsed();
        restore(&vols);
        damage(&vols[bad]);
        let t = std::time::Instant::now();
        let hinted_pass = rr_repair_volumes(&dir, &vols, None, Some(&hint));
        let pass_hinted = t.elapsed();
        assert_eq!(blind_pass.hard_failures + hinted_pass.hard_failures, 0);
        eprintln!(
            "round {round}: end-to-end blind {blind:.2?} hinted {hinted:.2?} ({:.2}x); RR pass alone blind {pass_blind:.2?} ({:.0} MB read) hinted {pass_hinted:.2?} ({:.0} MB read, {:.0} MB skipped) ({:.1}x)",
            blind.as_secs_f64() / hinted.as_secs_f64(),
            blind_pass.bytes_scanned as f64 / 1e6,
            hinted_pass.bytes_scanned as f64 / 1e6,
            hinted_pass.bytes_skipped as f64 / 1e6,
            pass_blind.as_secs_f64() / pass_hinted.as_secs_f64()
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_damaged_volume_without_a_record_still_fails_the_rung_under_a_hint() {
    use rars::rar50::{CompressedEntry, Rar50VolumeWriter, WriterOptions};
    let dir = temp_dir("norecord");
    let data = payload(100_000, 2246822519);
    let entries = [CompressedEntry {
        name: b"inner/data.bin",
        data: &data,
        mtime: None,
        attributes: 0o100644,
        host_os: 1,
    }];
    // No recovery record anywhere.
    let volumes = Rar50VolumeWriter::new(WriterOptions::default())
        .compressed_entries(&entries)
        .max_payload_per_volume(64 * 1024)
        .finish()
        .unwrap();
    let mut vols = Vec::new();
    for (index, bytes) in volumes.iter().enumerate() {
        let p = dir.join(format!("set.part{:02}.rar", index + 1));
        std::fs::write(&p, bytes).unwrap();
        vols.push(p);
    }
    let range = damage(&vols[1]);
    assert_the_fixture_is_really_damaged(&dir);
    let mut hint = DamageHint::default();
    for (i, v) in vols.iter().enumerate() {
        let ranges = if i == 1 { vec![range] } else { Vec::new() };
        hint.insert(v.file_name().unwrap().to_str().unwrap(), size(v), ranges);
    }
    // The intact volumes are skipped, the damaged one has nothing to
    // repair with: that is the old "could not save the set", and the
    // skips must not promote it into an extraction attempt.
    assert!(!try_rar_rr_repair_hinted(&dir, None, Some(&hint)));
    assert!(!dir.join("inner").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A volume named AT the component cap must still reach its recovery
/// record.
///
/// `rr_repair_volume` claims a unique temp beside the volume BEFORE it
/// has looked at the archive at all, and it used to spell that temp
/// `path.with_extension("rrtmp{n}")`. `with_extension` REPLACES, so it
/// grows whenever the new extension is longer than the old, and `.rar`
/// -> `.rrtmp0` always is: a leaf at 255 bytes - which is what
/// `sanitize_out_name` hands back for any long posted name, capping being
/// what produced it - becomes 258, and `create_new` refuses it with
/// `ENAMETOOLONG` (measured on APFS 31 Aug 2026: 255 creates, 256 does
/// not). The whole loop then ran out of candidates and the RR pass gave
/// up on the volume before reading a byte of it.
///
/// Driven through a `.rar` that is NOT an archive, which is exactly what
/// `collect_rar_volumes` hands this function - it takes any `.rar`-suffixed
/// entry - and which puts the answer one step past the temp claim: the
/// error names the SIGNATURE, so reaching it proves the temp was taken.
/// A pre-fix tree cannot get there; it fails at the claim.
#[test]
fn a_volume_named_at_the_cap_gets_past_the_repair_temp_claim() {
    let dir = std::env::temp_dir().join(format!(
        "nzbfast-rrtmpcap-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let name = nzbkit::disk::sanitize_out_name(&format!("{}.rar", "y".repeat(400)));
    assert_eq!(name.len(), 255, "the premise moved");
    let vol = dir.join(&name);
    std::fs::write(&vol, b"not an archive at all").unwrap();

    let e = super::rr_repair_volume(&vol, None).expect_err("nothing here is repairable");
    assert!(
        e.to_string().contains("not a RAR5 volume"),
        "the temp claim must be the step this gets PAST, not the one it \
         dies at: {e}"
    );
    // And the claim cleans up after itself, whatever name it took.
    let strays: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|x| x.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains("rrtmp"))
        .collect();
    assert!(strays.is_empty(), "repair temps left behind: {strays:?}");

    let _ = std::fs::remove_dir_all(&dir);
}

/// The RR pass over an ENCRYPTED set derives its RAR 5 key once, not
/// once per volume (research/RAR-PERF-AUDIT-2026-09-02.md, round 2).
///
/// No counting hook reaches this crate (rars keeps `derive_count`
/// `cfg(test)`-private), so this is a timing: the same header-encrypted
/// ten-volume set opened through one shared session (`rr_repair_volume_in`,
/// the production loop's shape) against one fresh session per volume
/// (`rr_repair_volume`, the pre-fix shape). PBKDF2-HMAC-SHA256 at 2^15
/// rounds is milliseconds even with SHA extensions, so nine of them
/// saved clear the noise of a `-m0` parse by a wide margin. The set
/// carries no recovery record, so every volume answers `NoRecord` and
/// the parse is all the pass does.
///
/// Needs an external `rar` (RAR_BIN, default `rar` on PATH) to write a
/// `-hp` set; skips with a note when there is none. `#[ignore]` because
/// it is a timing, run by hand.
#[test]
#[ignore]
fn encrypted_rr_pass_derives_the_key_once_per_set() {
    let bin = std::env::var("RAR_BIN").unwrap_or_else(|_| "rar".into());
    let dir = temp_dir("enc-once");
    std::fs::write(dir.join("payload.bin"), payload(5 << 20, 0x9e37_79b9)).unwrap();
    let st = std::process::Command::new(&bin)
        .current_dir(&dir)
        .args([
            "a",
            "-m0",
            "-ep",
            "-idq",
            "-v2m",
            "-hpPW",
            "encset.rar",
            "payload.bin",
        ])
        .status();
    let Ok(st) = st else {
        eprintln!("skipping: no `rar` binary (set RAR_BIN)");
        return;
    };
    assert!(st.success(), "rar a failed: {st}");
    let mut vols: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "rar"))
        .collect();
    vols.sort();
    assert!(
        vols.len() >= 10,
        "expected a ten-volume set, got {}",
        vols.len()
    );

    let time = |shared: bool| {
        let t = std::time::Instant::now();
        let mut session = rars::ReadSession::new(rars::ArchiveReadOptions::with_optional_password(
            Some(b"PW"),
        ));
        for v in &vols {
            let r = if shared {
                rr_repair_volume_in(&mut session, v, Some("PW"))
            } else {
                rr_repair_volume(v, Some("PW"))
            };
            assert!(
                matches!(r, Ok(RrRepair::NoRecord)),
                "{}: {r:?}",
                v.display()
            );
        }
        t.elapsed()
    };
    // Warm the page cache and the code path once, then pair the arms.
    let _ = time(true);
    let mut per_volume = Vec::new();
    let mut shared = Vec::new();
    for _ in 0..3 {
        per_volume.push(time(false));
        shared.push(time(true));
    }
    let min = |v: &[std::time::Duration]| v.iter().min().copied().unwrap();
    eprintln!(
        "{} volumes: per-volume sessions {:?}, one shared session {:?}",
        vols.len(),
        min(&per_volume),
        min(&shared)
    );
    assert!(
        min(&shared) < min(&per_volume),
        "a shared session must beat a session per volume: {shared:?} vs {per_volume:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
