//! The native (in-process) unrar path on disk: what `try_unrar*` does to a
//! directory of volumes, and the ladder it walks when a volume is missing,
//! damaged or passworded.

use super::*;

fn temp_dir(tag: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("nzbfast-native-unrar-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn native_path_extracts_compressed_multivolume_set() {
    use rars::rar50::{CompressedEntry, Rar50VolumeWriter, WriterOptions};
    let dir = temp_dir("multivol");
    let payload: Vec<u8> = (0..200_000u32)
        .flat_map(|i| (i.wrapping_mul(2654435761)).to_le_bytes())
        .collect();
    let entries = [CompressedEntry {
        name: b"inner/data.bin",
        data: &payload,
        mtime: None,
        attributes: 0o100644, // Unix host: attributes are the file mode
        host_os: 1,
    }];
    let volumes = Rar50VolumeWriter::new(WriterOptions::default())
        .compressed_entries(&entries)
        .max_payload_per_volume(64 * 1024)
        .finish()
        .unwrap();
    assert!(volumes.len() > 1, "expected a multivolume set");
    for (index, bytes) in volumes.iter().enumerate() {
        std::fs::write(dir.join(format!("set.part{:02}.rar", index + 1)), bytes).unwrap();
    }

    assert!(try_unrar(&dir, None));
    let extracted = std::fs::read(dir.join("inner").join("data.bin")).unwrap();
    assert_eq!(extracted, payload);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A compressed, split, multivolume RAR5 set on disk - the shape
/// TODO 101 exists for. Returns the volume paths in set order.
fn write_multivolume_set(dir: &std::path::Path, payload: &[u8]) -> Vec<PathBuf> {
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
        .finish()
        .unwrap();
    assert!(volumes.len() > 1, "expected a multivolume set");
    volumes
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            let p = dir.join(format!("set.part{:02}.rar", index + 1));
            std::fs::write(&p, bytes).unwrap();
            p
        })
        .collect()
}

/// TODO 101: with eating armed, a verified set extracts correctly AND
/// leaves no volume behind - the deletions happen DURING extraction,
/// which is what makes the peak one volume rather than two whole
/// copies. The payload check is the half that matters: a mode that
/// frees space by breaking the extraction would pass a "the volumes
/// are gone" assertion on its own.
#[test]
fn eating_extracts_the_payload_and_leaves_no_volume_behind() {
    let dir = temp_dir("eat-volumes");
    let payload: Vec<u8> = (0..200_000u32)
        .flat_map(|i| (i.wrapping_mul(2654435761)).to_le_bytes())
        .collect();
    let volumes = write_multivolume_set(&dir, &payload);

    let _arm = crate::eatvol::EatArm::new(
        crate::eatvol::decide(
            crate::eatvol::EatMode::Always,
            true,
            false,
            crate::eatvol::forecast(&dir, crate::eatvol::volume_bytes(&volumes), false),
        )
        .eats(),
    );
    assert!(try_unrar(&dir, None));

    let extracted = std::fs::read(dir.join("inner").join("data.bin")).unwrap();
    assert_eq!(extracted, payload, "the payload must survive the eating");
    for v in &volumes {
        assert!(!v.exists(), "{} outlived the extraction", v.display());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Bug sweep 2026-08-06 (H1): the vendored extractor decides
/// success on the DECODED bytes and drops the entry writer
/// afterwards, and BufWriter's Drop swallows its flush error - so
/// an ENOSPC/EIO on the final buffered tail used to publish a
/// short file as a verified extraction. The deferred-flush wrapper
/// must catch what Drop would have swallowed.
#[test]
fn a_swallowed_flush_failure_is_recorded_not_lost() {
    use std::io::Write as _;
    struct FailingFlush;
    impl std::io::Write for FailingFlush {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("no space left on device"))
        }
    }
    let failed: std::sync::Arc<std::sync::Mutex<Option<String>>> =
        std::sync::Arc::new(std::sync::Mutex::new(None));
    {
        let mut w = DeferredFlushWriter {
            inner: std::io::BufWriter::new(FailingFlush),
            failed: failed.clone(),
        };
        assert!(w.write_all(b"the final sub-8k tail").is_ok());
        // Dropped without an explicit flush - exactly what the
        // extractor does once the member's checksum has verified.
    }
    assert!(
        failed.lock().unwrap().is_some(),
        "the flush error vanished in Drop"
    );
}

/// The bomb guard may only spend space that has actually come back.
///
/// The eating path used to add the WHOLE volume set to the budget
/// before a byte was written, on the reasoning that the volumes were
/// about to be handed back. The engine does hand them back - but for
/// the commonest set of all (one member split across every volume)
/// it hands back NOTHING until the whole payload is written, because
/// a pending split holds every consumption callback. So the guard
/// waved through an extraction that could not fit and the real
/// filesystem stopped it instead: ENOSPC on a disk with nothing left.
///
/// This is the accounting rule underneath that, tested directly -
/// a free-space seam is not reachable from a unit test, but the
/// arithmetic that made the seam wrong is.
#[test]
fn the_bomb_guard_credits_only_space_that_came_back() {
    use std::io::Write as _;
    let budget = BombBudget::fixed(1_000);
    let credit = budget.credit_handle();
    assert_eq!(budget.limit(), 1_000, "a promise is not space");

    let written = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut w = BombGuardWriter {
        inner: Vec::new(),
        written: written.clone(),
        budget: budget.clone(),
    };
    assert!(w.write_all(&[0u8; 900]).is_ok());
    // Still over the line, because nothing has been freed yet: this
    // is exactly the write that used to be allowed on the strength
    // of volumes that were still sitting on the disk.
    assert!(
        w.write_all(&[0u8; 200]).is_err(),
        "the guard spent space the disk did not have"
    );

    // A volume actually removed credits its bytes, and only then.
    credit.fetch_add(500, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(budget.limit(), 1_500);
    let mut w2 = BombGuardWriter {
        inner: Vec::new(),
        written,
        budget,
    };
    assert!(
        w2.write_all(&[0u8; 300]).is_ok(),
        "space that came back must be spendable"
    );
}

/// The gate that matters most: an UNVERIFIED set is never eaten,
/// whatever the mode says - so a retry still has the volumes and
/// re-downloads nothing. Driven through `decide` rather than by
/// hand-setting the arm, because the composition of the two is the
/// thing that could regress.
#[test]
fn an_unverified_set_keeps_every_volume() {
    let dir = temp_dir("eat-unverified");
    let payload: Vec<u8> = (0..120_000u32)
        .flat_map(|i| (i.wrapping_mul(2246822519)).to_le_bytes())
        .collect();
    let volumes = write_multivolume_set(&dir, &payload);

    let _arm = crate::eatvol::EatArm::new(
        crate::eatvol::decide(
            // `always` plus a disk with nothing on it - every reason
            // to eat except the one that counts.
            crate::eatvol::EatMode::Always,
            false,
            true,
            crate::eatvol::Forecast {
                free: 0,
                volumes: crate::eatvol::volume_bytes(&volumes),
                encrypted: true,
            },
        )
        .eats(),
    );
    assert!(try_unrar(&dir, None));

    assert_eq!(
        std::fs::read(dir.join("inner").join("data.bin")).unwrap(),
        payload
    );
    for v in &volumes {
        assert!(v.exists(), "{} was eaten unverified", v.display());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Off is off. The same set, the same tight disk, consent given -
/// and nothing is touched during extraction, because the mode was
/// never turned on.
#[test]
fn the_off_mode_never_eats_however_tight_the_disk() {
    let dir = temp_dir("eat-off");
    let payload: Vec<u8> = (0..120_000u32)
        .flat_map(|i| (i.wrapping_mul(2654435761)).to_le_bytes())
        .collect();
    let volumes = write_multivolume_set(&dir, &payload);

    let _arm = crate::eatvol::EatArm::new(
        crate::eatvol::decide(
            crate::eatvol::EatMode::Off,
            true,
            true,
            crate::eatvol::Forecast {
                free: 0,
                volumes: crate::eatvol::volume_bytes(&volumes),
                encrypted: true,
            },
        )
        .eats(),
    );
    assert!(try_unrar(&dir, None));
    for v in &volumes {
        assert!(v.exists(), "{} was eaten with the mode off", v.display());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rr_repair_rescues_corrupted_volume_and_extracts() {
    use rars::rar50::{CompressedEntry, Rar50Writer, WriterOptions};
    let dir = temp_dir("rr-repair");
    let payload: Vec<u8> = (0..150_000u32)
        .flat_map(|i| (i.wrapping_mul(2246822519)).to_le_bytes())
        .collect();
    let entries = [CompressedEntry {
        name: b"video.bin",
        data: &payload,
        mtime: None,
        attributes: 0o100644,
        host_os: 1,
    }];
    let mut archive = Rar50Writer::new(WriterOptions::default())
        .compressed_entries(&entries)
        .recovery_percent(Some(20))
        .finish()
        .unwrap();
    // Corrupt a run of payload bytes well inside the archive.
    let start = archive.len() / 3;
    for byte in &mut archive[start..start + 2048] {
        *byte ^= 0x5a;
    }
    let path = dir.join("set.rar");
    std::fs::write(&path, &archive).unwrap();

    // The control: the damage is real, so a blind extraction refuses the
    // archive (staged - a refusal leaves nothing behind). Note what this
    // one does NOT pin: `Rar50Writer` has always stamped the whole-file
    // CRC on an unsplit entry, so reverting the 22 Aug volume-writer row
    // (vendor/rars/VENDORING.md - a split STORED member carried no CRC)
    // does not move it. The volume-set legs in `rrhint_tests.rs` are
    // where that regression is caught; this is the same discipline over
    // a single archive.
    assert!(
        !try_unrar(&dir, None),
        "the fixture must actually be corrupt"
    );
    assert!(!dir.join("video.bin").exists());

    assert!(try_rar_rr_repair(&dir, None));
    let extracted = std::fs::read(dir.join("video.bin")).unwrap();
    assert_eq!(extracted, payload);
    assert!(!dir.join("set.rrtmp").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rr_repair_raw_scan_rescues_a_volume_whose_headers_are_destroyed() {
    use rars::rar50::{CompressedEntry, Rar50Writer, WriterOptions};
    let dir = temp_dir("rr-raw-scan");
    let payload: Vec<u8> = (0..80_000u32)
        .flat_map(|i| (i.wrapping_mul(2246822519)).to_le_bytes())
        .collect();
    let entries = [CompressedEntry {
        name: b"video.bin",
        data: &payload,
        mtime: None,
        attributes: 0o100644,
        host_os: 1,
    }];
    let archive = Rar50Writer::new(WriterOptions::default())
        .compressed_entries(&entries)
        .recovery_percent(Some(20))
        .finish()
        .unwrap();

    // Wreck the headers so the archive cannot be parsed at all: this is
    // the last-chance path that used to read the whole volume, clone it,
    // and hand back a third copy.
    let mut damaged = archive.clone();
    for byte in &mut damaged[8..400] {
        *byte ^= 0xa5;
    }
    let path = dir.join("set.rar");
    std::fs::write(&path, &damaged).unwrap();
    assert!(
        rars::ArchiveReader::read_path_with_options(&path, rars::ArchiveReadOptions::default())
            .is_err(),
        "the test must actually exercise the raw-scan fallback"
    );

    assert!(try_rar_rr_repair(&dir, None));
    assert_eq!(
        std::fs::read(&path).unwrap(),
        archive,
        "the raw scan must restore the volume byte for byte"
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
fn rr_repair_raw_scan_leaves_the_original_alone_when_it_cannot_repair() {
    use rars::rar50::{CompressedEntry, Rar50Writer, WriterOptions};
    let dir = temp_dir("rr-raw-fail");
    let payload: Vec<u8> = (0..80_000u32)
        .flat_map(|i| (i.wrapping_mul(2246822519)).to_le_bytes())
        .collect();
    let entries = [CompressedEntry {
        name: b"video.bin",
        data: &payload,
        mtime: None,
        attributes: 0o100644,
        host_os: 1,
    }];
    let archive = Rar50Writer::new(WriterOptions::default())
        .compressed_entries(&entries)
        .recovery_percent(Some(1))
        .finish()
        .unwrap();

    // Headers destroyed AND far more damage than 1% can cover.
    let mut damaged = archive.clone();
    let end = damaged.len() * 3 / 4;
    for byte in &mut damaged[8..end] {
        *byte ^= 0xa5;
    }
    let path = dir.join("set.rar");
    std::fs::write(&path, &damaged).unwrap();

    assert!(!try_rar_rr_repair(&dir, None));
    assert_eq!(
        std::fs::read(&path).unwrap(),
        damaged,
        "a failed repair must leave the volume exactly as it found it"
    );
    assert!(
        !std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().contains("rrtmp")),
        "no repair temp may survive a failure"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rr_repair_leaves_unrepairable_volume_untouched() {
    use rars::rar50::{CompressedEntry, Rar50Writer, WriterOptions};
    let dir = temp_dir("rr-unrepairable");
    let payload: Vec<u8> = (0..100_000u32)
        .flat_map(|i| (i.wrapping_mul(374761393)).to_le_bytes())
        .collect();
    let entries = [CompressedEntry {
        name: b"video.bin",
        data: &payload,
        mtime: None,
        attributes: 0o100644,
        host_os: 1,
    }];
    let mut archive = Rar50Writer::new(WriterOptions::default())
        .compressed_entries(&entries)
        .recovery_percent(Some(1))
        .finish()
        .unwrap();
    // Corrupt far more than 1% RR can cover.
    let end = archive.len() * 3 / 4;
    for byte in &mut archive[64..end] {
        *byte ^= 0xa5;
    }
    let corrupted = archive.clone();
    let path = dir.join("set.rar");
    std::fs::write(&path, &archive).unwrap();

    assert!(!try_rar_rr_repair(&dir, None));
    assert_eq!(
        std::fs::read(&path).unwrap(),
        corrupted,
        "original untouched"
    );
    assert!(!dir.join("set.rrtmp").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rr_repair_skips_volumes_without_recovery_records() {
    use rars::rar50::{CompressedEntry, Rar50Writer, WriterOptions};
    let dir = temp_dir("rr-none");
    let entries = [CompressedEntry {
        name: b"data.bin",
        data: b"hello recovery-less world",
        mtime: None,
        attributes: 0o100644,
        host_os: 1,
    }];
    let archive = Rar50Writer::new(WriterOptions::default())
        .compressed_entries(&entries)
        .finish()
        .unwrap();
    std::fs::write(dir.join("set.rar"), &archive).unwrap();

    assert!(!try_rar_rr_repair(&dir, None));
    assert!(!dir.join("set.rrtmp").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn entry_paths_cannot_escape_output_dir() {
    let dir = std::path::Path::new("/tmp/out");
    assert!(sanitized_entry_path(dir, "../evil").is_none());
    assert!(sanitized_entry_path(dir, "a/../../evil").is_none());
    assert!(sanitized_entry_path(dir, "/abs/path").map(|p| p.starts_with(dir)) == Some(true));
    // Windows rejects the drive prefix outright; Unix keeps it as a
    // benign "C:" subdirectory. Either way it must stay under dir.
    let drive = sanitized_entry_path(dir, "C:\\evil");
    assert!(drive.is_none() || drive.is_some_and(|p| p.starts_with(dir)));
    assert_eq!(
        sanitized_entry_path(dir, "sub\\file.bin"),
        Some(dir.join("sub").join("file.bin"))
    );
    assert!(sanitized_entry_path(dir, "").is_none());
}

#[test]
fn drive_relative_component_cannot_escape_on_windows() {
    let dir = std::path::Path::new("/tmp/out");
    // A drive prefix only parses at byte 0, so these forms reach `push`
    // as ordinary components and used to wipe the staging dir.
    for name in ["sub/C:evil.dll", "x/D:payload.exe", "a\\b\\C:evil.dll"] {
        let p = sanitized_entry_path_for(dir, name, true).expect("kept, not escaped");
        assert!(p.starts_with(dir), "{name} escaped to {p:?}");
        assert!(
            !p.to_string_lossy().contains(':'),
            "{name} kept a drive-relative colon"
        );
    }
    // Unix keeps ':' (legal and common in release names) but still may
    // not escape, and the ordinary success path is untouched.
    let p = sanitized_entry_path_for(dir, "Movie: The Sequel/a.mkv", false).unwrap();
    assert_eq!(p, dir.join("Movie: The Sequel").join("a.mkv"));
}
