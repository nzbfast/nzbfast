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

/// An archive entry with a component no filesystem will create is
/// CAPPED here rather than at any of the writers, and that placement is
/// the whole point: this function's result is both the path the entry is
/// written to and the filesystem-IDENTITY key the module compares on
/// (`extract_one_zip`'s duplicate-target dedup, `resumeout::plan`'s "did
/// the chase publish exactly here" test). Capping at a writer would
/// shorten one end of that comparison and not the other, and two members
/// that resolve to ONE path would stop being seen as one and race on the
/// pool, each verifying only its own CRC over interleaved bytes.
///
/// Nothing that works today changes: 255 bytes creates and 300 is
/// `ENAMETOOLONG` for both `mkdir` and `create` (measured on APFS,
/// 31 Aug 2026), so every name shortened here is one the write refused.
#[test]
fn an_overlong_entry_component_is_capped_where_the_key_and_the_path_are_one() {
    let dir = std::env::temp_dir().join(format!("nzbfast-entrycap-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let long = "L".repeat(300);

    // Every component the extractor will have to create is writable -
    // and it really creates, which is what the byte count stands in for.
    let p = sanitized_entry_path(&dir, &format!("sub/{long}.bin")).expect("kept, not escaped");
    let rel = p.strip_prefix(&dir).expect("stayed under dir");
    for c in rel.components() {
        let n = c.as_os_str().to_string_lossy();
        assert!(n.len() <= 255, "{} bytes: {n}", n.len());
    }
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, b"x").expect("the capped path must be creatable");

    // Deterministic, so the key a second reader computes is the key the
    // writer used - and distinct per input, so two overlong members do
    // not collapse onto one file and race.
    assert_eq!(
        Some(p.clone()),
        sanitized_entry_path(&dir, &format!("sub/{long}.bin"))
    );
    assert_ne!(
        Some(p.clone()),
        sanitized_entry_path(&dir, &format!("sub/{}.bin", "M".repeat(300)))
    );

    // A FLAT overlong member is now spelled exactly as the in-stream
    // side spells it, so `resumeout::plan` matches where it used to fall
    // back to byte zero. The two sanitizers are allowed to disagree (the
    // plan tolerates it), but agreeing is strictly better and is what
    // capping both ends bought.
    let flat = format!("{long}.mkv");
    assert_eq!(
        sanitized_entry_path(&dir, &flat),
        Some(nzbkit::disk::join_out_name(
            &dir,
            &nzbkit::disk::sanitize_out_name(&flat)
        ))
    );

    // AND THE TREE CASE, which is the last one that parted (31 Aug
    // 2026). This side has always capped the component in place and
    // kept the tree; the in-stream side REFUSED an overlong component
    // and flattened the whole path, so `VIDEO_TS/<300>.VOB` came back
    // as two different names - not merely two shapes, two different
    // hash tags, because one hashed the flattened whole and the other
    // hashed the component. Both now compose
    // `cap_component(sanitize_filename_for(c))` per component, so there
    // is one spelling. Assert it against the in-stream function rather
    // than against a literal: a pin on the literal would still pass if
    // BOTH sides moved together to something unwritable.
    let tree = format!("VIDEO_TS/{long}.VOB");
    assert_eq!(
        sanitized_entry_path(&dir, &tree),
        Some(nzbkit::disk::join_out_name(
            &dir,
            &nzbkit::disk::sanitize_out_name(&tree)
        )),
        "the disk and in-stream spellings of an overlong member inside a \
         tree parted, so a resume refetches it from byte zero"
    );
    assert!(
        nzbkit::disk::sanitize_out_name(&tree).contains('/'),
        "the in-stream side flattened the tree, which is what this closed"
    );

    // The two are still allowed to part on DEPTH and TOTAL, and that is
    // a decision rather than an oversight - `None` here aborts the whole
    // extraction where `None` there only means "flatten", so this side
    // must not grow those limits. Pinned so a lane that "fixes" the
    // remaining disagreement has to read that reasoning first (it is on
    // `nzbkit::disk::sanitize_relpath_for`).
    let deep = (0..20)
        .map(|i| format!("d{i}"))
        .collect::<Vec<_>>()
        .join("/");
    let deep_disk = sanitized_entry_path(&dir, &deep).expect("kept, not escaped");
    assert_eq!(
        deep_disk.strip_prefix(&dir).unwrap().components().count(),
        20,
        "the disk side grew a depth limit, which turns a deep archive \
         from extracted into failed"
    );
    assert!(
        !nzbkit::disk::sanitize_out_name(&deep).contains('/'),
        "the in-stream side stopped flattening past MAX_DEPTH"
    );

    // And a name that fits is untouched, so nothing that works changes.
    assert_eq!(
        sanitized_entry_path(&dir, "sub/file.bin"),
        Some(dir.join("sub").join("file.bin"))
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// An archive entry whose components are each legal but whose JOINED
/// path is past the filesystem's ceiling used to take the whole archive
/// down, and the cost was never limited to that entry.
///
/// Measured on origin/main, 31 Aug 2026: a zip carrying `ordinary.bin`
/// and one member of 8 components of 200 bytes failed
/// `extract_one_zip` outright with `ENAMETOOLONG` - raised by
/// `create_dir_all` in the pre-vetting loop, which runs before a single
/// payload byte is written, so `ordinary.bin` was not extracted either -
/// one awkward entry, and the user got nothing.
///
/// Refusing in `sanitized_entry_path` would have bought that same
/// outcome by a shorter route, since every caller turns `None` into an
/// aborted extraction. So the budget answers with the flat capped NAME
/// instead, and it is the SAME function the in-stream side falls back
/// to - which is why the agreement below is asserted against
/// `sanitize_out_name` rather than against a literal: a pin on the
/// literal would still pass if both sides moved together to something
/// unwritable.
#[test]
fn an_over_budget_entry_lands_flat_instead_of_failing_the_archive() {
    use nzbkit::zip::fixtures::{Spec, zip_of};
    let dir = temp_dir("overbudget");
    let out = dir.join("stage");
    let published = dir.join("pub");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::create_dir_all(&published).unwrap();

    let long: String = (0..8)
        .map(|i| format!("{}{i}", "d".repeat(199)))
        .collect::<Vec<_>>()
        .join("/");
    assert!(long.len() > 1023, "{} bytes", long.len());
    assert!(
        long.split('/').all(|c| c.len() <= 255),
        "every component must be LEGAL, or the per-component cap is what \
         this row exercises and the total budget is unfalsified"
    );

    // The name: flat, capped, and spelled exactly as the in-stream
    // sanitizer spells it, so `resumeout::plan` matches instead of
    // falling back to byte zero.
    let target = sanitized_entry_path(&out, &long).expect("a long name is not a hostile one");
    let rel = target.strip_prefix(&out).unwrap();
    assert_eq!(rel.components().count(), 1, "{rel:?}");
    assert_eq!(
        Some(target.clone()),
        Some(nzbkit::disk::join_out_name(
            &out,
            &nzbkit::disk::sanitize_out_name(&long)
        )),
        "the disk and in-stream spellings of an over-budget member parted"
    );
    // Deterministic and distinct, so two over-budget members cannot
    // collapse onto one file and race on the pool.
    assert_eq!(Some(target.clone()), sanitized_entry_path(&out, &long));
    let other: String = (0..8)
        .map(|i| format!("{}{i}", "e".repeat(199)))
        .collect::<Vec<_>>()
        .join("/");
    assert_ne!(Some(target.clone()), sanitized_entry_path(&out, &other));

    // And the outcome that actually matters: the archive extracts, and
    // the innocent sibling is written.
    let arch = zip_of(&[
        Spec::stored("ordinary.bin", b"good payload"),
        Spec::stored(&long, b"long payload"),
    ]);
    let zp = dir.join("a.zip");
    std::fs::write(&zp, &arch).unwrap();
    extract_one_zip(&out, &published, &[zp], None).expect("one long entry must not fail the zip");
    assert_eq!(
        std::fs::read(out.join("ordinary.bin")).unwrap(),
        b"good payload",
        "the sibling member was lost to another entry's name"
    );
    assert_eq!(std::fs::read(&target).unwrap(), b"long payload");

    // DEPTH is still not a limit on this side, and that is a decision -
    // `None` here aborts the archive, so a merely-deep tree must not be
    // refused. The reasoning is on `nzbkit::disk::sanitize_relpath_for`.
    let deep = (0..20)
        .map(|i| format!("d{i}"))
        .collect::<Vec<_>>()
        .join("/");
    let deep_disk = sanitized_entry_path(&out, &deep).expect("kept, not escaped");
    assert_eq!(
        deep_disk.strip_prefix(&out).unwrap().components().count(),
        20,
        "the disk side grew a depth limit, which turns a deep archive from \
         extracted into failed"
    );

    // A name that fits is untouched, so nothing that works changes.
    assert_eq!(
        sanitized_entry_path(&out, "sub/file.bin"),
        Some(out.join("sub").join("file.bin"))
    );
    let _ = std::fs::remove_dir_all(&dir);
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

/// Two zip entries the VOLUME files as one object - NFC and NFD spellings
/// of the same accented name - used to be two keys in the extractor's
/// dedupe guard and one inode on disk, so both reached the writer pool,
/// each `File::create`d the same path and each verified only its own CRC
/// over a file holding interleaved bytes from both. The guard now keys by
/// `file_object_id`, which is the volume's own answer, and groups the
/// collision onto ONE worker in archive order.
///
/// Asserted against what the filesystem under `$TMPDIR` actually does
/// rather than against the platform: a case-insensitive volume is not by
/// definition normalization-insensitive, and Linux CI's is neither. The
/// probe below creates one spelling and asks for the other, which is the
/// only honest oracle for "does this volume merge these two names".
#[test]
fn zip_entries_the_volume_files_as_one_object_serialize_instead_of_racing() {
    use nzbkit::zip::fixtures::{Spec, zip_of};
    let dir = temp_dir("zipnorm");
    let out = dir.join("stage");
    let published = dir.join("pub");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::create_dir_all(&published).unwrap();

    // U+00E9 against 'e' + U+0301 COMBINING ACUTE: one grapheme, two
    // spellings, and APFS files them as one object.
    let nfc = "\u{00E9}.txt";
    let nfd = "e\u{0301}.txt";
    assert_ne!(nfc, nfd, "the fixture must be two distinct byte strings");

    let probe = dir.join("probe");
    std::fs::create_dir_all(&probe).unwrap();
    std::fs::write(probe.join(nfc), b"x").unwrap();
    let merges = std::fs::read(probe.join(nfd)).is_ok();

    // THE PREMISE, pinned deterministically, because the end state below
    // only catches the race when it happens to lose - measured at 2 runs
    // in 8 on the dev box with the old key, which is a test that reports
    // a green over a live defect three times in four. What is exact is
    // WHY the old key missed it: the volume answers "one object" and the
    // spellings the guard used to compare do not.
    if merges {
        let a = nzbkit::disk::file_object_id(&probe.join(nfc));
        let b = nzbkit::disk::file_object_id(&probe.join(nfd));
        assert!(
            a.is_some() && a == b,
            "the volume merges these: {a:?} {b:?}"
        );
        assert_ne!(
            nfc.to_lowercase(),
            nfd.to_lowercase(),
            "lowercasing the two spellings, which is what this guard used \
             to key on, must still tell them apart - that gap IS the bug"
        );
        assert_ne!(
            nzbkit::disk::case_fold_key(nfc),
            nzbkit::disk::case_fold_key(nfd),
            "and the stronger fold does not close it either, which is why \
             the key is the volume's own answer and not a fold"
        );
    }

    // The sizes are the oracle and they are chosen, not arbitrary. A
    // symmetric pair makes the race a coin toss - measured at 2 losses
    // in 8 runs on the dev box, which is a green over a live defect
    // three times in four, and repeating the round does not compound it
    // because the scheduling is stable inside one process. A FIRST entry
    // far larger than the LAST inverts that: two workers start together,
    // the small one finishes first, and the big one's `File::create`
    // truncation and trailing writes then land on top, so a raced
    // extraction ends up holding the FIRST entry and a serialized one
    // holds the last. Measured with these sizes: 8 losses in 8 runs on
    // the old key, 0 in 8 on this one.
    let first = vec![b'A'; 16 * 1024 * 1024];
    let last = vec![b'Z'; 1024];
    let arch = zip_of(&[Spec::stored(nfc, &first), Spec::stored(nfd, &last)]);
    let zp = dir.join("norm.zip");
    std::fs::write(&zp, &arch).unwrap();
    for round in 0..3 {
        let out = out.join(format!("r{round}"));
        std::fs::create_dir_all(&out).unwrap();
        extract_one_zip(&out, &published, std::slice::from_ref(&zp), None)
            .expect("the archive must extract");

        let landed: Vec<PathBuf> = std::fs::read_dir(&out)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        if merges {
            assert_eq!(
                landed.len(),
                1,
                "the volume files these as one object, so one file lands: {landed:?}"
            );
            // The LAST entry's payload, WHOLE - which is what a
            // one-at-a-time unpack leaves, and what neither an interleave
            // nor a truncation can produce.
            assert_eq!(
                std::fs::read(out.join(nfd)).unwrap(),
                last,
                "round {round}: the collision was raced or truncated \
                 instead of serialized"
            );
            // And through the other spelling, since it is one object.
            assert_eq!(std::fs::read(out.join(nfc)).unwrap(), last);
        } else {
            assert_eq!(landed.len(), 2, "round {round}: {landed:?}");
            assert_eq!(std::fs::read(out.join(nfc)).unwrap(), first);
            assert_eq!(std::fs::read(out.join(nfd)).unwrap(), last);
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The plain duplicate-name case, which is legal in the format and has
/// always extracted last-wins. It used to get there by DROPPING every
/// entry but the last; it now gets there by writing the group in archive
/// order on one worker, and the outcome a caller sees is unchanged.
#[test]
fn duplicate_zip_entry_names_extract_last_wins() {
    use nzbkit::zip::fixtures::{Spec, zip_of};
    let dir = temp_dir("zipdup");
    let out = dir.join("stage");
    let published = dir.join("pub");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::create_dir_all(&published).unwrap();

    let first = vec![b'1'; 300_000];
    let last = vec![b'9'; 200_000];
    let arch = zip_of(&[
        Spec::stored("dup.bin", &first),
        Spec::stored("other.bin", b"untouched"),
        Spec::stored("dup.bin", &last),
    ]);
    let zp = dir.join("dup.zip");
    std::fs::write(&zp, &arch).unwrap();
    extract_one_zip(&out, &published, &[zp], None).expect("a duplicate name is not a failure");

    assert_eq!(
        std::fs::read(out.join("dup.bin")).unwrap(),
        last,
        "the last entry must win, whole"
    );
    assert_eq!(std::fs::read(out.join("other.bin")).unwrap(), b"untouched");
    let landed = std::fs::read_dir(&out).unwrap().count();
    assert_eq!(landed, 2, "exactly the two distinct output files");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The other half of the same guard: entries that share NO output object
/// must still be independent units of work, so the pool is as wide as it
/// was before the bucketing landed. The observable is that every member
/// lands with its own payload - an over-folding key would merge two of
/// them into one bucket and the earlier one's file would simply not
/// exist.
#[test]
fn distinct_zip_entry_names_stay_independent() {
    use nzbkit::zip::fixtures::{Spec, zip_of};
    let dir = temp_dir("zipwide");
    let out = dir.join("stage");
    let published = dir.join("pub");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::create_dir_all(&published).unwrap();

    let payloads: Vec<Vec<u8>> = (0..6u8)
        .map(|i| vec![b'a' + i; 100_000 + i as usize])
        .collect();
    let names: Vec<String> = (0..6).map(|i| format!("member{i}.bin")).collect();
    let specs: Vec<Spec> = names
        .iter()
        .zip(&payloads)
        .map(|(n, p)| Spec::stored(n, p))
        .collect();
    let zp = dir.join("wide.zip");
    std::fs::write(&zp, zip_of(&specs)).unwrap();
    extract_one_zip(&out, &published, &[zp], None).expect("six distinct members must extract");

    for (n, p) in names.iter().zip(&payloads) {
        assert_eq!(&std::fs::read(out.join(n)).unwrap(), p, "{n}");
    }
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), 6);
    let _ = std::fs::remove_dir_all(&dir);
}
