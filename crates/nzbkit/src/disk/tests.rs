//! Unit tests for [`crate::disk`].
//!
//! Split out of `disk.rs` on 22 Aug 2026: the file was at 2,990 raw
//! lines against the size gate's 3,000 ceiling, with 922 of them this
//! module, so no production change could land in it at all. Same
//! ratchet, and the same seam, as `smart.rs` -> `smart/tests.rs` and
//! `pool.rs` -> `pool/rig_tests.rs` before it. A pure move: nothing
//! here changed, and `use super::*` still names `disk`.

use super::*;

/// C1: the RAM-aware drop-behind default. The threshold itself is a
/// measured crossover (see the main.rs call site); what these rows
/// pin is the SHAPE - tighter-of-two source selection, the boundary
/// landing on "2 GiB is on, above is off", and a failed probe
/// reading as a big box rather than a small one.
#[test]
fn drop_cache_auto_is_memory_tiered() {
    let g = 1u64 << 30;
    // Small boxes: on. Roomy boxes: off.
    assert!(drop_cache_auto_for(Some(g), None));
    assert!(drop_cache_auto_for(Some(2 * g), None)); // boundary: on
    assert!(!drop_cache_auto_for(Some(2 * g + 1), None));
    assert!(!drop_cache_auto_for(Some(32 * g), None));
    // A 1 GB docker limit on a 32 GB host is a small box (the
    // cgroup, not the metal, is where reclaim pressure lives).
    assert!(drop_cache_auto_for(Some(32 * g), Some(g)));
    // A roomy limit does not shrink a roomy host into the slow arm.
    assert!(!drop_cache_auto_for(Some(32 * g), Some(16 * g)));
    // cgroup-only reading (host RAM probe failed): the limit decides.
    assert!(drop_cache_auto_for(None, Some(g)));
    // Both probes failed: not small - keep the big-box default.
    assert!(!drop_cache_auto_for(None, None));
}

/// The pacer's watermark step: the stride rule as measured on 6 Aug,
/// plus the completion rule that closes the small-file blind spot
/// (see `pace_step`). Each row is one write_at's view of the world.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn pace_step_strides_and_flushes_small_files_once() {
    const MB: u64 = 1 << 20;
    const PARKED: u64 = u64::MAX;
    // (written, covered, due, size, stride); covered == written in
    // the duplicate-free rows.
    // Big file mid-write: crossing the watermark advances it a stride.
    assert_eq!(
        pace_step(16 * MB, 16 * MB, 16 * MB, 500 * MB, 32 * MB),
        Some(48 * MB)
    );
    // Below the watermark, not complete: nothing fires.
    assert_eq!(
        pace_step(15 * MB, 15 * MB, 16 * MB, 500 * MB, 32 * MB),
        None
    );
    // The blind spot: an 8 MB file never reaches the 16 MB watermark,
    // so completion is its ONE flush - and it parks the watermark.
    assert_eq!(
        pace_step(8 * MB, 8 * MB, 16 * MB, 8 * MB, 32 * MB),
        Some(PARKED)
    );
    // Parked stays parked: a duplicate article after completion (or
    // any later write) must not flush again.
    assert_eq!(pace_step(9 * MB, 8 * MB, PARKED, 8 * MB, 32 * MB), None);
    // A stride crossing that IS the completion parks in one step
    // rather than scheduling a watermark nothing will ever cross.
    assert_eq!(
        pace_step(48 * MB, 48 * MB, 48 * MB, 48 * MB, 32 * MB),
        Some(PARKED)
    );
    // Codex 7 Aug M3: duplicate/repair spans push `written` past
    // `size` while unique coverage still has a gap - the watermark
    // must KEEP STRIDING (never park), or the genuine tail writes
    // unpaced and the burst the pacer exists to prevent comes back
    // on exactly the jobs with rewrites.
    assert_eq!(
        pace_step(80 * MB, 72 * MB, 80 * MB, 80 * MB, 32 * MB),
        Some(112 * MB),
        "aggregate traffic reaching size is not completion"
    );
    assert_eq!(
        pace_step(90 * MB, 79 * MB, 112 * MB, 80 * MB, 32 * MB),
        None
    );
    // ...and the park lands when unique coverage really completes.
    assert_eq!(
        pace_step(96 * MB, 80 * MB, 112 * MB, 80 * MB, 32 * MB),
        Some(PARKED)
    );
    // Unknown size (0): no completion rule, the stride still paces.
    assert_eq!(pace_step(8 * MB, 8 * MB, 16 * MB, 0, 32 * MB), None);
    assert_eq!(
        pace_step(16 * MB, 16 * MB, 16 * MB, 0, 32 * MB),
        Some(48 * MB)
    );
    // A saturated stride (parse_pace_mb turns an absurd env value
    // into u64::MAX) must not overflow the next watermark - it
    // parks, it does not wrap into a per-write flush storm.
    assert_eq!(
        pace_step(16 * MB, 16 * MB, 16 * MB, 0, PARKED),
        Some(PARKED)
    );
    assert_eq!(
        pace_step(16 * MB, 16 * MB, 16 * MB, 0, PARKED - 16 * MB),
        Some(PARKED)
    );
}

/// Fault-injecting writer for the disk-full halt rig: forwards to a
/// real [`FileWriter`] until `budget` bytes have been accepted, then
/// every write fails with `StorageFull` - the shape of a volume that
/// filled mid-download.
struct FaultWriter {
    inner: FileWriter,
    budget: AtomicU64,
}

impl FaultWriter {
    fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        let left = self.budget.load(Ordering::Relaxed);
        if (data.len() as u64) > left {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "No space left on device (injected)",
            ));
        }
        self.budget.fetch_sub(data.len() as u64, Ordering::Relaxed);
        self.inner.write_at(offset, data)
    }
}

/// The rig itself: writes land until the injected volume fills, the
/// failure carries `StorageFull`, and `storage_exhausted` classifies
/// it - which is exactly the signal the decode consumers halt on.
#[test]
fn fault_writer_storage_full_after_n_bytes_classifies() {
    let dir = std::env::temp_dir().join(format!("nzbfast-faultw-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("fills.bin");
    let w = FaultWriter {
        inner: FileWriter::create(&path, 16).unwrap(),
        budget: AtomicU64::new(8),
    };
    w.write_at(0, b"abcd").unwrap();
    w.write_at(4, b"efgh").unwrap();
    let e = w.write_at(8, b"ijkl").unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::StorageFull, "{e}");
    assert!(storage_exhausted(&e), "{e}");
    // What landed before the fill is intact - the journal's resume
    // contract rests on that.
    assert_eq!(&std::fs::read(&path).unwrap()[..8], b"abcdefgh");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn storage_exhausted_kinds_and_raw_codes() {
    for kind in [
        io::ErrorKind::StorageFull,
        io::ErrorKind::QuotaExceeded,
        io::ErrorKind::ReadOnlyFilesystem,
        io::ErrorKind::WriteZero,
    ] {
        assert!(storage_exhausted(&io::Error::new(kind, "x")), "{kind:?}");
    }
    assert!(!storage_exhausted(&io::Error::new(
        io::ErrorKind::PermissionDenied,
        "x"
    )));
    assert!(!storage_exhausted(&io::Error::other("x")));
    #[cfg(unix)]
    {
        // ENOSPC and EROFS classify; 112 is EHOSTDOWN here, NOT
        // Windows' ERROR_DISK_FULL - the platform trap this gate
        // exists for.
        assert!(storage_exhausted(&io::Error::from_raw_os_error(28)));
        assert!(storage_exhausted(&io::Error::from_raw_os_error(30)));
        assert!(!storage_exhausted(&io::Error::from_raw_os_error(112)));
    }
    #[cfg(windows)]
    {
        assert!(storage_exhausted(&io::Error::from_raw_os_error(112)));
        assert!(storage_exhausted(&io::Error::from_raw_os_error(39)));
        assert!(!storage_exhausted(&io::Error::from_raw_os_error(28)));
    }
}

/// [`bomb_verdict`] must survive every wrapper the verdict travels
/// inside before an extraction ladder reads it.
///
/// The refusal is raised at a writer and consumed two crates away: a
/// chased group turns it into `chase failed: {e}` (chase.rs) and the
/// disk pass carries it up an anyhow chain. Matching the whole sentence
/// would have missed both, and missing it is silent - the ladder just
/// runs the next unpacker, which on 22 Aug 2026 was an external unrar
/// with no budget and a disk it then filled.
#[test]
fn the_bomb_verdict_is_recognised_through_its_wrappers() {
    assert!(bomb_verdict(BOMB_VERDICT));
    assert!(bomb_verdict(&format!("chase failed: {BOMB_VERDICT}")));
    assert!(bomb_verdict(&format!("parsing volumes: {BOMB_VERDICT}")));
    assert!(bomb_verdict(&io::Error::other(BOMB_VERDICT).to_string()));
    // Ordinary demote reasons, which must keep their ladder.
    for why in [
        "compressed or encrypted entries",
        "inner file failed its stored CRC",
        "held-bytes cap: header stash",
        "chase failed: worker died",
        // A real disk that filled under an unbudgeted write is NOT this
        // verdict: nothing refused it, so retrying after freeing space
        // is exactly the right move and the ladder stays open.
        "No space left on device (os error 28)",
    ] {
        assert!(!bomb_verdict(why), "'{why}' would lose its unpack ladder");
    }
}

/// A parked writer keeps its bytes and its identity, refuses writes while
/// it is parked, and comes back usable. The refusal is the point: a write
/// that landed while an external par2 owned the file would be overwritten
/// by the repair without a word.
#[test]
fn park_refuses_writes_then_unpark_restores_the_writer() {
    let dir = std::env::temp_dir().join(format!("nzbfast-park-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("payload.bin");
    let w = FileWriter::create(&path, 8).unwrap();
    w.write_at(0, b"abcd").unwrap();

    w.park().unwrap();
    let e = w.write_at(4, b"efgh").unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::NotConnected, "{e}");
    let mut buf = [0u8; 4];
    assert_eq!(
        w.read_at(&mut buf, 0).unwrap_err().kind(),
        io::ErrorKind::NotConnected
    );
    // Parked syncs are a no-op, not a failure: park() already synced, so
    // erroring here would fail a job whose bytes are all safely on disk.
    w.sync().unwrap();
    // The bytes written before parking reached disk, and the file itself
    // is untouched - that is what the external tool repairs against.
    assert_eq!(&std::fs::read(&path).unwrap()[..4], b"abcd");

    w.unpark().unwrap();
    w.unpark().unwrap(); // idempotent - error paths may double-unpark
    w.write_at(4, b"efgh").unwrap();
    w.read_at(&mut buf, 4).unwrap();
    assert_eq!(&buf, b"efgh");
    assert_eq!(&std::fs::read(&path).unwrap()[..8], b"abcdefgh");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The soak 11 Aug shape (sab3287-stall): PAR2 deobfuscation renames the
/// file on disk while the writer's handle is open, then the external-par2
/// fallback parks and unparks. Without `note_renamed`, unpark reopens the
/// CREATION path, gets ENOENT, and the whole job dies with "reopening our
/// output handles after the external par2" - on the success path too,
/// throwing away a completed repair.
#[test]
fn unpark_follows_a_published_rename() {
    let dir = std::env::temp_dir().join(format!("nzbfast-repark-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let obfuscated = dir.join("cb124762578234ca");
    let real = dir.join("yay.part04.rar");
    let w = FileWriter::create(&obfuscated, 8).unwrap();
    w.write_at(0, b"abcd").unwrap();

    // The publish: on-disk rename under the live handle.
    std::fs::rename(&obfuscated, &real).unwrap();
    w.note_renamed(real.clone());
    assert_eq!(w.current_path(), real);

    w.park().unwrap();
    w.unpark().unwrap();
    w.write_at(4, b"efgh").unwrap();
    assert_eq!(&std::fs::read(&real).unwrap()[..8], b"abcdefgh");
    let _ = std::fs::remove_dir_all(&dir);
}

/// X5-06/08/19 OWED item 6 (31 Aug 2026): [`FileWriter::unpark`] is a
/// by-name REOPEN, and it happens at the one moment in a job when
/// something else has been renaming inodes around - the external par2
/// has just run, and `park_for_repair` closed our handle on purpose so
/// it could. The row said this had no fixture. It does now, and it is
/// two questions rather than one.
///
/// It cannot land bytes OUTSIDE the output directory the way X5-06 and
/// X5-08 could, because it never creates - what it could do is bind the
/// writer to a foreign inode, so every later `write_at` and every
/// reader admitted after the repair would be talking to somebody else's
/// file while the job reported success.
#[cfg(unix)]
#[test]
fn unpark_refuses_an_alias_that_appeared_while_parked() {
    const SENTINEL: &[u8] = b"nothing in the job may touch this inode\n";
    let dir = std::env::temp_dir().join(format!("nzbfast-unparkalias-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    let out = dir.join("out");
    let outside = dir.join("outside");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    let sentinel = outside.join("sentinel.bin");
    std::fs::write(&sentinel, SENTINEL).unwrap();

    let path = out.join("payload.bin");
    let w = FileWriter::create(&path, 8).unwrap();
    w.write_at(0, b"abcd").unwrap();
    w.park().unwrap();

    // The window par2 owns: our handle is closed and only the name is
    // left. Something replaces the name with a link out of the job.
    std::fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(&sentinel, &path).unwrap();
    let e = w.unpark().unwrap_err();
    assert!(
        e.to_string().contains("an alias is in the way"),
        "unexpected error: {e}"
    );
    assert!(
        w.write_at(4, b"efgh").is_err(),
        "a refused unpark must stay parked"
    );
    assert_eq!(
        std::fs::read(&sentinel).unwrap(),
        SENTINEL,
        "unpark bound the writer to an inode outside the job"
    );

    // And the reason `Existing` is its own mode rather than `Keep`: a
    // file that has GONE is `NotFound`, never an empty one created here
    // and handed back as the repaired payload.
    std::fs::remove_file(&path).unwrap();
    let e = w.unpark().unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{e}");
    assert!(
        !path.exists(),
        "unpark created the file it was told was missing"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The whole point on Windows: while parked, an EXCLUSIVE open of the file
/// succeeds. That is exactly what par2cmdline does, and a handle we still
/// held made it report the target missing and decline to repair.
#[cfg(windows)]
#[test]
fn a_parked_file_can_be_opened_exclusively() {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;
    // share mode 0 - what par2cmdline asks for.
    let exclusive = |p: &Path| OpenOptions::new().read(true).share_mode(0).open(p);

    let dir = std::env::temp_dir().join(format!("nzbfast-excl-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("payload.bin");
    let w = FileWriter::create(&path, 4).unwrap();
    w.write_at(0, b"abcd").unwrap();

    assert!(exclusive(&path).is_err(), "a live writer must block par2");
    w.park().unwrap();
    drop(exclusive(&path).expect("a parked writer must let par2 in"));
    w.unpark().unwrap();
    assert!(exclusive(&path).is_err(), "unpark must retake the handle");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Sweep 8, M4: entering an EXTERNAL repair takes custody of the
/// file, and a reader admitted after it must be reading the
/// repaired bytes, not racing the child that is writing them.
///
/// The plain end-of-job `park` must NOT claim custody - `postproc`
/// parks the outputs of every finished job and never unparks them,
/// so a claim there would lock every later reader out of a finished
/// job's files for good. That half is the second assertion.
#[test]
fn an_external_repair_takes_custody_of_the_file_and_hands_it_back() {
    let dir = std::env::temp_dir().join(format!("nzbfast-custody-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("payload.bin");
    let w = Arc::new(FileWriter::create(&path, 8).unwrap());
    w.write_at(0, b"abcdefgh").unwrap();

    // Ordinary admission, and the handle follows current_path.
    let (_f, lease) = w.open_read().expect("a live file admits readers");
    assert!(!lease.revoked());
    assert!(!w.under_repair());
    drop(lease);

    w.park_for_repair().unwrap();
    assert!(w.under_repair(), "the external tool owns the file");

    // A PROBE arriving mid-repair does not wait at all (bug sweep
    // 22 Aug 2026): it has a "not yet" to give.
    let t0 = std::time::Instant::now();
    let kind = w.try_open_read().map(|_| ()).unwrap_err().kind();
    assert_eq!(kind, std::io::ErrorKind::ResourceBusy);
    assert!(t0.elapsed() < std::time::Duration::from_millis(100));

    // A reader arriving mid-repair WAITS for it rather than being
    // told the file is gone - par2cmdline on a repairable set is
    // seconds, and a player that seeks into one wants its bytes.
    let w2 = w.clone();
    let unparker = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(150));
        w2.unpark().unwrap();
    });
    let t0 = std::time::Instant::now();
    let (_f, lease) = w.open_read().expect("admitted once the repair is done");
    assert!(
        t0.elapsed() >= std::time::Duration::from_millis(100),
        "the open must have waited out the repair, not raced the child"
    );
    assert!(!lease.revoked());
    assert!(!w.under_repair());
    unparker.join().unwrap();
    drop(lease);

    // The end-of-job park is a handle release, not a repair.
    w.park().unwrap();
    assert!(!w.under_repair(), "a cleanup park must not claim custody");
    w.open_read()
        .expect("a finished job's outputs stay readable forever");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Codex F-21 (22 Aug 2026): `open_read` used to admit a reader under
/// the custody gate, RELEASE the gate, and only then open the path. A
/// repair claiming custody in that gap owned the file before the
/// descriptor existed - and Unix repair does not drain readers, so the
/// open landed on whatever inode the child had mid-rewrite, bytes
/// nobody had published. The fix opens UNDER the gate: the descriptor
/// is ordered before any later `repairing = true`, so a reader admitted
/// before the claim always holds the pre-repair inode and hears about
/// the repair through its lease like every other survivor.
///
/// The seam (`open_barrier`, consumed by one trip) parks the reader at
/// the open; on the fixed code the parked reader HOLDS the gate, so the
/// repair's claim waits and the rewrite cannot start until the
/// descriptor exists. The child rewrites the way par2cmdline really
/// does - damaged target renamed aside, fresh bytes on a NEW inode - so
/// which inode the reader's descriptor holds is the whole verdict.
#[test]
fn a_reader_admitted_before_a_repair_never_opens_the_childs_inode() {
    let dir = std::env::temp_dir().join(format!("nzbfast-f21-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("payload.bin");
    let w = Arc::new(FileWriter::create(&path, 8).unwrap());
    w.write_at(0, b"old-old!").unwrap();

    let entered = Arc::new(std::sync::Barrier::new(2));
    let released = Arc::new(std::sync::Barrier::new(2));
    w.custody.st.lock_ok().open_barrier = Some((entered.clone(), released.clone()));
    let reader = {
        let w = w.clone();
        std::thread::spawn(move || w.open_read())
    };
    entered.wait(); // admitted, standing at the open
    // The external repair arrives NOW and rewrites the target the way
    // par2cmdline does: rename the damaged file aside, fresh inode in
    // its place. On the fixed code the claim waits for the gate the
    // parked reader holds; on the pre-fix shape it all completes while
    // the reader stands there.
    let repair = {
        let w = w.clone();
        let path = path.clone();
        std::thread::spawn(move || {
            w.park_for_repair().unwrap();
            std::fs::rename(&path, path.with_extension("bin.1")).unwrap();
            std::fs::write(&path, b"mid-rew!").unwrap();
        })
    };
    // Long enough that the repair thread has certainly reached the
    // gate (fixed) or finished its rewrite (pre-fix shape).
    std::thread::sleep(std::time::Duration::from_millis(150));
    released.wait();
    let (f, lease) = reader
        .join()
        .unwrap()
        .expect("the admitted reader gets its handle");
    let mut buf = [0u8; 8];
    read_exact_at(&f, &mut buf, 0).unwrap();
    assert_eq!(
        &buf, b"old-old!",
        "the descriptor must be the pre-repair inode, not the child's half-written one"
    );
    repair.join().unwrap();
    // And the ordinary survivor contract still holds from here: the
    // repair finishes, the generation moves, the lease says reopen.
    w.unpark().unwrap();
    assert!(
        lease.needs_reopen(),
        "a reader that predates the repair is told to rebind"
    );
    drop(lease);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Sweep 8, M5b: par2cmdline does not repair in place, so a reader
/// that kept its handle across the repair is holding the DAMAGED
/// file - and M5 has just told it those bytes are good.
///
/// This is the rename par2cmdline really does (`<name>` -> `<name>.1`,
/// repaired data written fresh at `<name>`), and the assertions are
/// the contract `LiveRangeReader::rebind` is written against: no
/// reopen before the repair, none DURING it (the inode in place then
/// is nobody's), one afterwards, and none again once it is taken.
/// The integration half is `nzbfast`'s `stream_repair.rs`, which
/// needs a real par2 and skips without one - so this is the leg that
/// runs everywhere.
#[test]
fn a_reader_follows_an_external_repair_onto_its_new_inode() {
    let dir = std::env::temp_dir().join(format!("nzbfast-rebind-{}", std::process::id()));
    let job = dir.join("Some.Release.2026");
    std::fs::create_dir_all(&job).unwrap();
    let path = job.join("payload.bin");
    let w = FileWriter::create(&path, 8).unwrap();
    w.write_at(0, b"abcd0000").unwrap();

    // The player, reading the file with its hole still in it.
    let (old_handle, lease) = w.open_read().unwrap();
    let mut buf = [0u8; 8];
    read_exact_at(&old_handle, &mut buf, 0).unwrap();
    assert_eq!(&buf, b"abcd0000");
    assert!(!lease.needs_reopen(), "nothing has repaired anything yet");

    w.park_for_repair().unwrap();
    assert!(
        !lease.needs_reopen(),
        "mid-repair the file on disk is the child's, not ours"
    );
    // par2cmdline, to the letter: the damaged target is renamed
    // aside and the repaired data goes to a NEW inode.
    std::fs::rename(&path, job.join("payload.bin.1")).unwrap();
    std::fs::write(&path, b"abcdefgh").unwrap();
    w.unpark().unwrap();

    // The writer never noticed - it reopened by current_path.
    w.read_at(&mut buf, 0).unwrap();
    assert_eq!(&buf, b"abcdefgh");
    // The reader did, and its old handle is still the damaged file:
    // without the reopen this is what the response serves, over a
    // span M5 has just published as covered.
    read_exact_at(&old_handle, &mut buf, 0).unwrap();
    assert_eq!(&buf, b"abcd0000");
    assert!(lease.needs_reopen(), "the repair moved the file under us");

    // A reader that arrives AFTER the repair is already current.
    let (_f, fresh) = w.open_read().unwrap();
    assert!(!fresh.needs_reopen());

    // The end-of-job park is a handle release, not a repair: it may
    // neither invent a rebind nor swallow the one still owed.
    w.park().unwrap();
    w.unpark().unwrap();
    assert!(!fresh.needs_reopen(), "a cleanup park is not a repair");
    assert!(lease.needs_reopen(), "the pending rebind survives a park");

    // postproc, moving the finished job's folder out from under
    // `current_path` - which tracks the FILE's publish rename and
    // knows nothing about this one. A reopen that went by name
    // would ENOENT here, leave the response on the damaged inode,
    // and the whole fix would come down to whether the player read
    // again in the ~200 ms before the move (measured 22 Aug 2026 -
    // it did not, and the test failed on exactly that).
    //
    // Windows has no captured handle to fall back FROM: its readers
    // were revoked before the child ran.
    #[cfg(not(windows))]
    {
        std::fs::rename(&job, dir.join("Some Release 2026")).unwrap();
        assert!(!w.current_path().exists(), "the by-path reopen is doomed");
    }

    let new_handle = w.reopen_read(&lease).unwrap();
    read_exact_at(&new_handle, &mut buf, 0).unwrap();
    assert_eq!(&buf, b"abcdefgh", "the reopen must land on the repair");
    assert!(!lease.needs_reopen(), "one repair, one reopen");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Sweep 8, M4, the Windows half and the reason the lease exists:
/// par2cmdline opens its targets with share mode 0, so a live range
/// response holding its own handle on the inode made a repairable
/// file report as missing. The lease is revoked on entry to repair
/// and the reader ends its response; `park_for_repair` waits for
/// the handle to go before the child is spawned.
#[cfg(windows)]
#[test]
fn a_revoked_reader_lets_the_external_tool_in() {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;
    let exclusive = |p: &Path| OpenOptions::new().read(true).share_mode(0).open(p);

    let dir = std::env::temp_dir().join(format!("nzbfast-revoke-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("payload.bin");
    let w = Arc::new(FileWriter::create(&path, 4).unwrap());
    w.write_at(0, b"abcd").unwrap();

    // The player: holds the handle until its lease is revoked,
    // exactly as `LiveRangeReader::read` does.
    let (f, lease) = w.open_read().unwrap();
    let reader = std::thread::spawn(move || {
        while !lease.revoked() {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        drop(f);
        drop(lease);
    });

    w.park_for_repair().unwrap();
    drop(exclusive(&path).expect("the repair must get an exclusive open"));
    reader.join().unwrap();
    w.unpark().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Sweep 8, M5: bytes an EXTERNAL tool wrote have to reach the
/// coverage map, or a live reader goes on treating repaired bytes
/// as a hole - waiting them out and then zero-filling over them.
/// They must NOT reach `written`, which counts physical writes
/// through this handle and feeds the job's disk rate.
#[test]
fn external_repair_coverage_publishes_without_charging_the_write_rate() {
    let dir = std::env::temp_dir().join(format!("nzbfast-extcov-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("payload.bin");
    let w = FileWriter::create(&path, 1024).unwrap();
    w.write_at(0, &[1u8; 256]).unwrap();
    w.write_at(768, &[1u8; 256]).unwrap();
    assert!(!w.covered(256, 512), "the middle is a hole");
    let wrote = w.written();

    // par2cmdline fills the hole outside the writer, then verifies.
    w.note_repaired(0, 1024);
    assert!(w.covered(0, 1024), "a verified repair covers the file");
    assert_eq!(
        w.written(),
        wrote,
        "an external tool's bytes are not this handle's write rate"
    );
    // Idempotent: a second pass over the same set republishes
    // nothing and cannot double-count.
    w.note_repaired(0, 1024);
    assert!(w.covered(0, 1024));
    let _ = std::fs::remove_dir_all(&dir);
}

/// The probe must never answer `Rotational` for something it could not
/// identify - an unknown answer clamps nothing, a wrong "spinning"
/// answer would throttle an SSD, a RAID array or an SMB share.
#[test]
fn storage_probe_never_guesses_rotational() {
    assert_eq!(
        detect_storage(Path::new("/nonexistent-nzbfast-probe")),
        Storage::Unknown
    );
    let here = detect_storage(Path::new("."));
    #[cfg(not(target_os = "linux"))]
    assert_eq!(here, Storage::Unknown, "only Linux exposes the flag");
    #[cfg(target_os = "linux")]
    assert!(
        matches!(
            here,
            Storage::Solid | Storage::Unknown | Storage::Rotational
        ),
        "{here:?}"
    );
}

/// The pacing-stride mapping: MB in, bytes out, 0 = explicitly off,
/// unset/garbage = defer to the process default. Through the pure
/// seam so the suite never mutates shared process env.
#[test]
fn pace_stride_parses_mb_zero_and_garbage() {
    assert_eq!(parse_pace_mb(Some("32")), Some(32 << 20));
    assert_eq!(parse_pace_mb(Some(" 8 ")), Some(8 << 20));
    assert_eq!(parse_pace_mb(Some("0")), Some(0), "0 is OFF, not unset");
    assert_eq!(parse_pace_mb(Some("lots")), None);
    assert_eq!(parse_pace_mb(Some("")), None);
    assert_eq!(parse_pace_mb(None), None);
    // Absurd values saturate instead of wrapping back under the cap.
    assert_eq!(parse_pace_mb(Some("18446744073709551615")), Some(u64::MAX));
}

/// The operator override names a profile in both directions, so a
/// misdetected array or a network mount can be corrected. Anything
/// else - unset, `auto`, a typo - defers to the probe.
#[test]
fn storage_override_maps_both_directions_and_defers_otherwise() {
    assert_eq!(
        storage_override(Some("rotational")),
        Some(Storage::Rotational)
    );
    assert_eq!(storage_override(Some("hdd")), Some(Storage::Rotational));
    assert_eq!(storage_override(Some("ssd")), Some(Storage::Solid));
    assert_eq!(storage_override(Some("solid")), Some(Storage::Solid));
    assert_eq!(storage_override(Some("auto")), None);
    assert_eq!(storage_override(Some("SSD")), None, "match is exact");
    assert_eq!(storage_override(None), None);
}

/// The clamp fires only for a spinning disk on a NAS-class box. Every
/// other combination must pass the caller's choice through untouched -
/// throttling a big box, an SSD, or storage we failed to identify would
/// cost real throughput (1 decoder is a third of 4 on fast hardware).
#[test]
fn rotational_clamp_only_bites_nas_class_boxes() {
    assert_eq!(decoders_for_storage(Storage::Rotational, 4, 4), 1);
    assert_eq!(decoders_for_storage(Storage::Rotational, 2, 8), 1);
    // Big box: a rotational device here is usually a wide array.
    assert_eq!(decoders_for_storage(Storage::Rotational, 8, 4), 4);
    assert_eq!(decoders_for_storage(Storage::Rotational, 32, 4), 4);
    // Never clamp on anything we did not positively identify as spinning.
    assert_eq!(decoders_for_storage(Storage::Unknown, 2, 4), 4);
    assert_eq!(decoders_for_storage(Storage::Solid, 2, 4), 4);
    // Already serial, or explicitly asked for one: nothing to say.
    assert_eq!(decoders_for_storage(Storage::Rotational, 2, 1), 1);
}

/// The spill path needs room for one writer per volume; the stock macOS
/// 256 is not enough for a 431-volume job.
///
/// Unix only, because the limit it is about is. Windows has no
/// RLIMIT_NOFILE: `std::fs::File` there is a Win32 HANDLE from
/// `CreateFileW`, and handles are bounded by kernel memory (millions),
/// not by a per-process soft cap anyone can raise. The CRT's own
/// 512-descriptor table is a different thing that Rust does not use. So
/// there is nothing to raise and `raise_fd_limit` reports 0 - which this
/// test asserted was "too low for the spill path", the reading that made
/// it fail the first time the suite ran on Windows.
#[cfg(unix)]
#[test]
fn fd_limit_is_raised_above_the_stock_soft_cap() {
    let got = raise_fd_limit();
    assert!(got >= 1024, "fd limit {got} too low for the spill path");
    // Idempotent: a second call must not lower what we already have.
    assert!(raise_fd_limit() >= got);
}

/// The other half of the contract above: on Windows the call must be a
/// harmless no-op rather than something that reports a limit the caller
/// might then size the spill path against.
#[cfg(windows)]
#[test]
fn fd_limit_is_a_no_op_where_there_is_no_such_limit() {
    assert_eq!(
        raise_fd_limit(),
        0,
        "nothing to raise on Windows - say so, don't invent one"
    );
}

/// Whichever branch `preallocate_capped` takes (raw fallocate where
/// the Linux fs supports it, plain set_len on macOS/tmpfs/zfs), the
/// observable contract is the same: the file spans `size` at create
/// and resume, and writes land at their offsets.
#[test]
fn preallocation_yields_correct_length_on_both_paths() {
    let dir = std::env::temp_dir().join(format!("nzbfast-prealloc-{}", std::process::id()));
    let path = dir.join("out.bin");

    let w = FileWriter::create(&path, 300_000).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 300_000);
    w.write_at(299_990, &[7u8; 10]).unwrap();
    w.sync().unwrap();
    drop(w);

    // Resume must keep the earlier bytes and still span `size`.
    let w = FileWriter::create_resume(&path, 300_000).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 300_000);
    let mut tail = [0u8; 10];
    w.read_at(&mut tail, 299_990).unwrap();
    assert_eq!(tail, [7u8; 10]);
    drop(w);

    // Zero-size files skip fallocate (EINVAL on len 0) but must
    // still truncate.
    let w = FileWriter::create(&path, 0).unwrap();
    drop(w);
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// BUG (HIGH): the in-stream extractor preallocated an
/// attacker-declared size. An inner file's `unpacked_size` is a RAR
/// header vint the poster controls, and on Linux `preallocate_capped`
/// is a real `fallocate` - so a few-hundred-KB post declaring terabytes
/// genuinely reserved the victim's free space until the finish-time
/// gates demoted the set. The ceiling bounds the RESERVATION.
#[test]
fn a_declared_size_past_the_ceiling_reserves_only_the_ceiling() {
    let dir = std::env::temp_dir().join(format!("nzbfast-cap-{}", std::process::id()));
    let path = dir.join("bomb.bin");
    const HUGE: u64 = 8 << 40; // 8 TiB "declared"
    const POSTED: u64 = 1 << 20; // what the NZB actually posted

    let w = FileWriter::create_capped(&path, HUGE, POSTED).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().len(),
        POSTED,
        "an attacker-declared size must not reserve past the posted ceiling"
    );
    // CRITICAL: `size` itself is NOT clamped - create_resume's stale
    // truncation and the reported extracted size both read it.
    assert_eq!(w.size, HUGE);
    // And the cap is a reservation bound, not a write bound: writing
    // past it extends the file normally.
    w.write_at(POSTED + 4096, &[9u8; 8]).unwrap();
    let mut got = [0u8; 8];
    w.read_at(&mut got, POSTED + 4096).unwrap();
    assert_eq!(got, [9u8; 8]);
    assert_eq!(std::fs::metadata(&path).unwrap().len(), POSTED + 4104);
    drop(w);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// THE test that matters: a wrong fix here silently de-optimises
/// every real download. A legitimate file that fits under the posted
/// ceiling must still be reserved IN FULL, on both create paths.
#[test]
fn a_legitimate_size_under_the_ceiling_still_preallocates_in_full() {
    let dir = std::env::temp_dir().join(format!("nzbfast-cap-ok-{}", std::process::id()));
    let path = dir.join("movie.bin");
    const SIZE: u64 = 4_000_000;
    const POSTED: u64 = 64_000_000;

    let w = FileWriter::create_capped(&path, SIZE, POSTED).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().len(),
        SIZE,
        "a legitimate file under the ceiling must be preallocated in full"
    );
    assert_eq!(w.size, SIZE);
    drop(w);

    let w = FileWriter::create_resume_capped(&path, SIZE, POSTED).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().len(), SIZE);
    drop(w);

    // Exactly at the ceiling is legitimate too (STORE unpacks 1:1, and
    // the posted count carries yEnc overhead on top).
    let w = FileWriter::create_capped(&path, POSTED, POSTED).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().len(), POSTED);
    drop(w);

    // No ceiling set = byte-for-byte the old behaviour.
    let w = FileWriter::create_capped(&path, SIZE, u64::MAX).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().len(), SIZE);
    drop(w);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The ceiling must never cost a resumed job its bytes: on the resume
/// path it may not shrink the file below what is already there, and
/// the stale-longer-file trim (down to `size`, which only ever frees
/// space) still has to happen.
#[test]
fn the_ceiling_never_shrinks_a_resumed_file() {
    let dir = std::env::temp_dir().join(format!("nzbfast-cap-res-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("out.bin");

    // 400 KB already on disk, a 1 KB ceiling, 8 TB declared: the
    // existing bytes stay.
    std::fs::write(&path, vec![0xAAu8; 400_000]).unwrap();
    let w = FileWriter::create_resume_capped(&path, 8 << 40, 1024).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 400_000);
    let mut head = [0u8; 4];
    w.read_at(&mut head, 0).unwrap();
    assert_eq!(head, [0xAA; 4]);
    drop(w);

    // Stale file LONGER than `size`: still trimmed to exactly `size`
    // even under a smaller ceiling - that shrinks, so it reserves
    // nothing.
    std::fs::write(&path, vec![0xAAu8; 500_000]).unwrap();
    let w = FileWriter::create_resume_capped(&path, 300_000, 1024).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 300_000);
    drop(w);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// BUG (MEDIUM): the decompression-bomb guard was installed only on
/// the disk and post-pass sinks, so it covered the fallback and not
/// the default in-stream path. The budget now rides the FileWriter,
/// and is SHARED - a bomb split over many inner files gets one
/// allowance, not one each.
#[test]
fn the_extract_budget_is_shared_and_charges_only_new_bytes() {
    let dir = std::env::temp_dir().join(format!("nzbfast-budget-{}", std::process::id()));
    let budget = std::sync::Arc::new(WriteBudget::new(1000));

    let a = FileWriter::create(&dir.join("a.bin"), 4096)
        .unwrap()
        .with_budget(budget.clone());
    let b = FileWriter::create(&dir.join("b.bin"), 4096)
        .unwrap()
        .with_budget(budget.clone());

    a.write_at(0, &[1u8; 600]).unwrap();
    assert_eq!(budget.used(), 600);
    // A repair span REWRITING bytes already counted must not be
    // charged twice - otherwise a healing job trips its own guard.
    a.write_at(0, &[2u8; 600]).unwrap();
    a.write_at(100, &[3u8; 200]).unwrap();
    assert_eq!(budget.used(), 600, "rewrites must not be charged");
    // Partial overlap charges only the new tail.
    a.write_at(500, &[4u8; 200]).unwrap();
    assert_eq!(budget.used(), 700);

    // The SECOND file draws on the same allowance and trips it.
    let e = b.write_at(0, &[5u8; 400]).unwrap_err();
    assert_eq!(
        e.to_string(),
        BOMB_VERDICT,
        "the verdict is a contract the extraction ladder reads back"
    );
    assert!(bomb_verdict(&e.to_string()), "unexpected error: {e}");
    // And it classifies as storage exhaustion, which is what makes
    // the consumer HALT the fetch on the first trip instead of
    // downloading and writing every remaining article past the
    // ceiling while counting each one as a decode/write error.
    assert!(
        storage_exhausted(&e),
        "a budget breach must halt the fetch: {e}"
    );

    // A writer with no budget is never charged (plain download slots).
    let c = FileWriter::create(&dir.join("c.bin"), 4096).unwrap();
    c.write_at(0, &[6u8; 100_000]).unwrap();
    drop((a, b, c));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// TODO 37 med1: a writer whose file is UNLINKED hands its charge back.
///
/// The drop-behind trim spills a chased archive's consumed prefix into
/// that archive's own path, and at depth > 0 that writer carries the
/// extraction budget - correctly, since the spill occupies the volume
/// beside the payload. But a chase that succeeds DELETES the spill
/// (`drop_slot_file`), and with no credit the bytes went on counting
/// for the rest of the job: several nested archives in one job could
/// refuse a legitimate extract as a decompression bomb. `abandon` is
/// the one statement every disown-and-unlink path makes
/// (`drop_slot_file`, `abandon_slot`, `delete_group_out_files`), so the
/// release rides it.
#[test]
fn abandoning_a_writer_credits_its_bytes_back_to_the_extract_budget() {
    let dir = std::env::temp_dir().join(format!("nzbfast-budget-rel-{}", std::process::id()));
    let budget = std::sync::Arc::new(WriteBudget::new(1000));

    let spill = FileWriter::create(&dir.join("inner.7z"), 4096)
        .unwrap()
        .with_budget(budget.clone());
    let out = FileWriter::create(&dir.join("F.bin"), 4096)
        .unwrap()
        .with_budget(budget.clone());

    spill.write_at(0, &[1u8; 600]).unwrap();
    out.write_at(0, &[2u8; 300]).unwrap();
    assert_eq!(budget.used(), 900);

    // The chase succeeded: the spilled prefix is unlinked, and only the
    // payload is still on the volume.
    spill.abandon();
    let _ = std::fs::remove_file(&spill.path);
    assert_eq!(budget.used(), 300, "the unlinked spill still counts");

    // Idempotent - `abandon` is sticky and is reached twice on some
    // demote paths (a slot abandoned, then its group swept).
    spill.abandon();
    assert_eq!(budget.used(), 300);

    // And the allowance really is back: what the spill had spent would
    // have tripped the guard before the credit.
    out.write_at(300, &[3u8; 600]).unwrap();
    assert_eq!(budget.used(), 900);
    let e = out.write_at(900, &[4u8; 200]).unwrap_err();
    assert!(bomb_verdict(&e.to_string()), "unexpected error: {e}");

    drop((spill, out));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `abandon_close` is the disown-and-unlink primitive: it must flag the
/// writer abandoned AND close the shared OS handle for every Arc clone
/// at once, and hand back the CURRENT path for the unlink.
///
/// The close is the load-bearing half, and it is why a bare `abandon()`
/// before an unlink was a disk leak: the handle lives in shared state,
/// clones of the Arc (the stream picker's snapshot, `routed_plain`, a
/// pending spill) outlive the slot, and on unix an unlinked file with
/// any live descriptor keeps its blocks. On the 30 Aug 2026 live
/// incident that pinned a 51.2 GB preallocated .mkv for over four
/// hours after its chase was demoted.
#[test]
fn abandon_close_closes_the_shared_handle_for_every_clone() {
    let dir = std::env::temp_dir().join(format!("nzbfast-abandon-close-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("movie.mkv");
    let w = std::sync::Arc::new(FileWriter::create(&path, 4096).unwrap());
    w.write_at(0, &[7u8; 64]).unwrap();
    // The stream picker's shape: a clone taken before the demote.
    let viewer = w.clone();

    let gone = w.abandon_close();
    assert_eq!(gone, path, "unrenamed writer unlinks its creation path");
    std::fs::remove_file(&gone).unwrap();

    assert!(viewer.is_abandoned(), "the flag reaches every clone");
    // The handle is CLOSED for the clone too - a read through the
    // shared state answers NotConnected, exactly as a parked writer
    // does, instead of quietly serving the unlinked inode.
    let mut buf = [0u8; 8];
    let e = viewer.read_at(&mut buf, 0).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::NotConnected, "{e}");
    // And a write through the clone cannot resurrect it.
    let e = viewer.write_at(64, &[1u8; 8]).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::NotConnected, "{e}");

    drop((w, viewer));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// And the unlink target follows a verified-name publish: after
/// `note_renamed` the creation name is ENOENT, so an unlink aimed there
/// would miss while the real file survived as a false artifact -
/// `abandon_close` must answer the CURRENT path.
#[test]
fn abandon_close_returns_the_renamed_path() {
    let dir = std::env::temp_dir().join(format!("nzbfast-abandon-renamed-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let created = dir.join("aGVsbG8.mkv");
    let published = dir.join("Real.Name.mkv");
    let w = FileWriter::create(&created, 64).unwrap();
    std::fs::rename(&created, &published).unwrap();
    w.note_renamed(published.clone());

    let gone = w.abandon_close();
    assert_eq!(gone, published);
    std::fs::remove_file(&gone).unwrap();
    drop(w);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A stale file LONGER than `size` at the resume path must be shrunk
/// to exactly `size` - fallocate never shrinks, so this pins the
/// unconditional set_len that precedes it (trailing garbage past
/// `size` would otherwise ship to the user for unparred files).
#[test]
fn create_resume_truncates_stale_longer_file() {
    let dir = std::env::temp_dir().join(format!("nzbfast-resume-trunc-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("out.bin");

    std::fs::write(&path, vec![0xAAu8; 500_000]).unwrap();
    let w = FileWriter::create_resume(&path, 300_000).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 300_000);
    // Bytes inside [0, size) survive the resume.
    let mut head = [0u8; 10];
    w.read_at(&mut head, 0).unwrap();
    assert_eq!(head, [0xAAu8; 10]);
    drop(w);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn out_of_order_writes_assemble_correctly() {
    let dir = std::env::temp_dir().join(format!("nzbfast-disk-test-{}", std::process::id()));
    let path = dir.join("out.bin");
    let data: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();

    let w = FileWriter::create(&path, data.len() as u64).unwrap();
    // Write the second half first, then the first.
    w.write_at(60_000, &data[60_000..]).unwrap();
    w.write_at(0, &data[..60_000]).unwrap();
    assert_eq!(w.written(), data.len() as u64);
    w.sync().unwrap();

    assert_eq!(std::fs::read(&path).unwrap(), data);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// note_written keeps `intervals` sorted, disjoint, and adjacency-
/// merged. Fuzz it against a brute-force byte-set oracle across
/// overlapping, adjacent, gap-filling and out-of-order spans.
#[test]
fn note_written_merges_like_a_byte_set() {
    let path = std::env::temp_dir().join(format!("nzbfast-iv-{}.bin", std::process::id()));
    let w = FileWriter::create(&path, 512).unwrap();
    let mut oracle = vec![false; 512];
    // A deterministic LCG picks spans; includes adjacency (b==c) and
    // full overlaps.
    let mut state = 0x1234_5678u64;
    let mut rng = || {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        (state >> 33) as usize
    };
    for _ in 0..2000 {
        let a = rng() % 500;
        let l = 1 + rng() % 40;
        let b = (a + l).min(512);
        w.note_written(a as u64, (b - a) as u64);
        for x in a..b {
            oracle[x] = true;
        }
        // Coverage must exactly match the oracle for a few probes.
        for _ in 0..4 {
            let qa = rng() % 500;
            let ql = 1 + rng() % 30;
            let qb = (qa + ql).min(512);
            let want = oracle[qa..qb].iter().all(|&c| c);
            assert_eq!(
                w.covered(qa as u64, (qb - qa) as u64),
                want,
                "covered({qa},{qb}) disagrees with oracle"
            );
        }
    }
    // The interval list must be sorted, disjoint and non-adjacent.
    let iv = w.intervals.lock().unwrap();
    for pair in iv.windows(2) {
        assert!(pair[0].1 < pair[1].0, "not disjoint/sorted: {iv:?}");
    }
    for &(s, e) in iv.iter() {
        assert!(s < e, "empty interval {iv:?}");
    }
    drop(iv);
    let _ = std::fs::remove_file(&path);
}

/// M4-66 (30 Aug 2026): the leading-dot trim was a many-to-one collapse
/// of two names that are both legal and distinct EVERYWHERE - Windows
/// folds trailing dots, never leading ones - so a PAR2 set declaring
/// `.movie.mkv` and `movie.mkv` had two payloads and one on-disk name.
/// The e2e half is `crates/nzbfast/tests/e2e_norar3/mod.rs`, which is
/// where the cost was measured; this is the rule it rests on.
#[test]
fn a_leading_dot_no_longer_collides_with_the_undotted_name() {
    // The row's own shape, both platform arms.
    for win in [false, true] {
        assert_ne!(
            sanitize_filename_for(".movie.mkv", win),
            sanitize_filename_for("movie.mkv", win),
            "leading-dot twin collapsed (windows={win})"
        );
        assert_eq!(sanitize_filename_for(".movie.mkv", win), "_movie.mkv");
        assert_eq!(sanitize_filename_for("movie.mkv", win), "movie.mkv");
    }
    // The whole RUN maps, one `_` per dot, so the depths stay distinct
    // from each other as well as from the bare name. Collapsing to a
    // single dot (or a single `_`) would re-create the same defect one
    // character over.
    let names = ["movie.mkv", ".movie.mkv", "..movie.mkv", "...movie.mkv"];
    let out: std::collections::HashSet<String> =
        names.iter().map(|n| sanitize_filename(n)).collect();
    assert_eq!(
        out.len(),
        names.len(),
        "a leading-dot depth collapsed: {out:?}"
    );
    // Visible, and portable: never hidden, and `_` is legal everywhere.
    // A dotfile is FURNITURE to this product - `smart::nzbname::
    // is_furniture` refuses to call one the main payload, `repair.rs`
    // skips it when scanning for unclaimed files, and `identity.rs`
    // will not take it as a release name - so preserving the dot would
    // have traded a name collision for an invisibility bug.
    for n in names {
        assert!(
            !sanitize_filename(n).starts_with('.'),
            "{n:?} landed hidden"
        );
    }
}

/// The TRAILING half of the same trim is deliberately UNCHANGED: Windows
/// really does fold `evil. ` onto `evil`, so a stable portable name has
/// to strip there, and mapping it to `_` would break the extension
/// (`movie.mkv.` -> `movie.mkv_`). That asymmetry is the whole scope of
/// M4-66; the trailing-dot and trailing-space collisions are M4-99 and
/// M4-80, which are their own rows and NOT fixed here. This pin exists
/// so that stays true by measurement rather than by intention.
#[test]
fn the_trailing_trim_is_untouched_by_the_leading_dot_mapping() {
    assert_eq!(sanitize_filename("Movie.mkv."), "Movie.mkv");
    assert_eq!(sanitize_filename("Movie.mkv "), "Movie.mkv");
    assert_eq!(sanitize_filename("Movie.mkv\u{a0}"), "Movie.mkv");
    assert_eq!(sanitize_filename("evil. "), "evil");
    // ...including the interleaved shape the old alternating trim chain
    // could not reach a fixed point on.
    assert_eq!(sanitize_filename("Movie.mkv . . "), "Movie.mkv");
}

/// M4-67 (30 Aug 2026): `char::is_control()` is general category Cc
/// only, so every Cf format character reached disk. U+202E is the sharp
/// one - it REORDERS the display, so the bytes end `.exe` and the
/// listing ends `.jpg` - and the zero-width family is the quiet one.
#[test]
fn format_characters_are_neutralised_like_control_characters() {
    // The RLO attack, exactly as the row spells it.
    assert_eq!(sanitize_filename("readme\u{202e}gpj.exe"), "readme_gpj.exe");
    // Zero-width twins are two files a person cannot tell apart; after
    // this they are one name, which the collision machinery can see.
    assert_eq!(sanitize_filename("movie\u{200b}.mkv"), "movie_.mkv");
    assert_eq!(sanitize_filename("mo\u{feff}vie.mkv"), "mo_vie.mkv");
    assert_eq!(sanitize_filename("mo\u{ad}vie.mkv"), "mo_vie.mkv");
    // The tag block is wholly invisible on every renderer.
    assert_eq!(sanitize_filename("a\u{e0041}b"), "a_b");
    // A name that is nothing BUT format characters still has to become
    // something openable rather than empty.
    assert_eq!(sanitize_filename("\u{202e}\u{200b}"), "__");
    // Ordinary names are untouched, including non-ASCII ones - this is
    // not a fold to ASCII.
    for n in [
        "Movie.mkv",
        "Fi\u{e9}vre.2024.mkv",
        "\u{41c}\u{43e}\u{441}\u{43a}\u{432}\u{430}.mkv",
    ] {
        assert_eq!(sanitize_filename(n), n, "{n:?} was altered");
    }
}

#[test]
fn sanitize() {
    assert_eq!(sanitize_filename("a/b\\c.rar"), "a_b_c.rar");
    // M4-66: the leading dots are MAPPED, not deleted - one `_` each -
    // so this no longer collides with a poster's plain "hidden". The
    // surrounding whitespace still goes.
    assert_eq!(sanitize_filename("  ..hidden  "), "__hidden");
    assert_eq!(sanitize_filename(""), "unnamed");
    // Traversal neutralisation (bug sweep: category/stem build the
    // download path). The result must be a single component - no
    // separators survive, so `join` can never escape the base.
    for s in ["../../../../tmp/pwned", "/tmp/abs", "..\\..\\win", "a/../b"] {
        let out = sanitize_filename(s);
        assert!(
            !out.contains('/') && !out.contains('\\'),
            "{s:?} -> {out:?}"
        );
        assert!(!out.starts_with('.'), "{s:?} -> {out:?}");
    }
    // Dots separated by spaces. The trim chain is not a fixed point:
    // stripping the outer dots exposes whitespace, and trimming THAT
    // exposes interior dots, so these used to come out as ".." and "." -
    // a component that escapes its parent, with `remove_dir_all` on the
    // delete-with-files path pointed at it. No separator is involved, so
    // the loop above never caught them.
    for s in [". .. .", ".. .. ..", ". . .", " .. ", "...", ". ."] {
        assert_eq!(sanitize_filename(s), "unnamed", "{s:?} escaped");
    }
    // ...and the same names as an on-disk path component stay contained.
    for s in [". .. .", ". . ."] {
        let joined = std::path::Path::new("/srv/dl").join(sanitize_filename(s));
        assert_eq!(joined, std::path::Path::new("/srv/dl/unnamed"), "{s:?}");
    }
    // A drive prefix is a separator too, on Windows. `Path::join` DISCARDS
    // the base when the joined name carries a prefix, so "C:evil.dll" wrote
    // outside the download dir entirely (into the cwd on C: - for the
    // installed app, the directory holding nzbfast.exe, i.e. first in the
    // DLL search order). "x.mkv:s" is the NTFS alternate-data-stream half:
    // the bytes go into the stream and the visible file is left 0 bytes.
    // Asserted through the `_for` seam so this holds on Unix CI too.
    for s in ["C:evil.dll", "payload.mkv:hidden", "\\\\?\\C:\\x", "C:/x"] {
        let out = sanitize_filename_for(s, true);
        assert!(!out.contains(':'), "{s:?} -> {out:?}");
        assert!(
            std::path::Path::new(&out).components().count() == 1,
            "not a single component: {s:?} -> {out:?}"
        );
    }
    // Unix keeps ':' - it is legal there and common in release names.
    assert_eq!(
        sanitize_filename_for("Movie: The Sequel.mkv", false),
        "Movie: The Sequel.mkv"
    );
    // Control characters (incl. embedded NUL/newline/tab) are replaced.
    let ctl = sanitize_filename("ev\u{7}il\nname\t.mkv");
    assert!(
        !ctl.chars().any(|c| c.is_control()),
        "control char survived: {ctl:?}"
    );
    // Trailing dot/space that Windows would strip.
    assert_eq!(sanitize_filename("evil. "), "evil");
    // Windows reserved device names get a prefix so File::create can't
    // open a device; real names with those as a substring are untouched.
    assert_eq!(sanitize_filename("CON"), "_CON");
    assert_eq!(sanitize_filename("con.txt"), "_con.txt");
    assert_eq!(sanitize_filename("COM1"), "_COM1");
    assert_eq!(sanitize_filename("LPT9.dat"), "_LPT9.dat");
    assert_eq!(sanitize_filename("COM0"), "COM0"); // not a real device
    assert_eq!(sanitize_filename("console.log"), "console.log"); // substring only
    assert_eq!(sanitize_filename("company"), "company");
    // Unicode superscript device names that Windows folds to COM1/LPT1.
    assert_eq!(sanitize_filename("COM\u{B9}"), "_COM\u{B9}");
    assert_eq!(sanitize_filename("LPT\u{B2}.dat"), "_LPT\u{B2}.dat");
    // Trailing-$ console/clock device handles.
    assert_eq!(sanitize_filename("CLOCK$"), "_CLOCK$");
    assert_eq!(sanitize_filename("CONIN$"), "_CONIN$");
    assert_eq!(sanitize_filename("CONOUT$"), "_CONOUT$");
}

/// A §94 A in-place REPLAY charges the extraction budget without
/// writing, and that charge was not recorded in the writer's own tally
/// - so `abandon` refunded nothing for it and the next container in the
/// job was refused with BOMB_VERDICT over bytes no longer on the
/// volume. `note_covered` now mirrors `write_at`'s ordering.
#[test]
fn a_replayed_range_is_credited_back_when_its_writer_is_abandoned() {
    let dir = std::env::temp_dir().join(format!("nzbfast-budget-replay-{}", std::process::id()));
    let budget = std::sync::Arc::new(WriteBudget::new(1000));

    let spill = FileWriter::create(&dir.join("inner.7z"), 4096)
        .unwrap()
        .with_budget(budget.clone());
    let out = FileWriter::create(&dir.join("F.bin"), 4096)
        .unwrap()
        .with_budget(budget.clone());

    // The bytes are already at this offset from the interrupted run, so
    // the resume publishes coverage instead of rewriting them.
    spill.note_covered(0, 600).unwrap();
    assert_eq!(budget.used(), 600);
    // A replay of the same range is not charged twice.
    spill.note_covered(0, 600).unwrap();
    assert_eq!(budget.used(), 600);

    spill.abandon();
    let _ = std::fs::remove_file(&spill.path);
    assert_eq!(budget.used(), 0, "the replayed bytes must be refunded");

    // And the allowance really is usable again by the next container.
    out.write_at(0, &[1u8; 900]).unwrap();
    assert_eq!(budget.used(), 900);

    drop((spill, out));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// [`chunk_len`] clamps in u64, so a span of 4 GiB or more still yields
/// positive progress.
///
/// The assertions that matter are the 32-bit ones, and they are written
/// so they hold on EVERY target: `chunk_len(4 GiB, 64 KiB)` must be
/// 64 KiB, not 0. The narrow-first spelling this helper replaces -
/// `(remaining as usize).min(cap)` - answers 0 there wherever `usize` is
/// 32 bits, which is the shipped armv7 beta, and 0 is either an infinite
/// loop (a decrementing reader makes no progress) or a false EOF (every
/// consumer in this tree reads `Ok(0)` as the end of the source).
///
/// Nothing here can fail on a 64-bit host by construction, which is
/// exactly why the class went unseen: this test earns its keep under
/// nightly's armv7-cross job, and as the one place the contract is
/// written down as executable text.
#[test]
fn chunk_len_clamps_in_u64_so_a_huge_span_still_makes_progress() {
    const G4: u64 = 1u64 << 32;
    const BUF: usize = 64 << 10;

    assert_eq!(super::chunk_len(G4, BUF), BUF, "exactly 4 GiB");
    assert_eq!(super::chunk_len(G4 * 3, BUF), BUF, "a multiple of 4 GiB");
    assert_eq!(super::chunk_len(G4 + 7, BUF), BUF, "just past 4 GiB");
    assert_eq!(super::chunk_len(u64::MAX, BUF), BUF);

    // The near-miss the class funnels through: a remaining span whose
    // low 32 bits are small still hands back those bytes, and the NEXT
    // call - now on an exact multiple - must not answer zero.
    assert_eq!(super::chunk_len(G4 + 7, BUF), BUF);
    assert_eq!(super::chunk_len(7, BUF), 7);

    // Ordinary spans are untouched.
    assert_eq!(super::chunk_len(0, BUF), 0, "an empty span takes nothing");
    assert_eq!(super::chunk_len(100, BUF), 100);
    assert_eq!(super::chunk_len(BUF as u64 + 1, BUF), BUF);
    assert_eq!(super::chunk_len(500, 0), 0, "an empty buffer takes nothing");
}

/// W4-14 (30 Aug 2026): [`copy_file_cow`] is a CLONE where the volume
/// has one and a plain copy where it does not, and the caller cannot
/// tell which ran - so what is pinned is the part that must hold on
/// every arm. Deliberately NOT asserted: that a clone happened. This
/// runs on APFS here, on ext4 in CI and on NTFS on the Windows shards,
/// and a test demanding a reflink would be red on two of the three
/// while saying nothing about correctness.
#[test]
fn copy_file_cow_reproduces_the_bytes_on_every_arm() {
    let dir = std::env::temp_dir().join(format!("nzbfast-cowcopy-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("src.bin");
    // Past one clone extent and not a round number of them.
    let data: Vec<u8> = (0..300_007u32)
        .map(|i| (i.wrapping_mul(37) >> 3) as u8)
        .collect();
    std::fs::write(&src, &data).unwrap();

    let dst = dir.join("dst.bin");
    assert_eq!(copy_file_cow(&src, &dst).unwrap(), data.len() as u64);
    assert!(
        std::fs::read(&dst).unwrap() == data,
        "clone/copy lost bytes"
    );

    // The clone and the copy must not share a future: a write through
    // one destination is invisible to the source. On a reflink that is
    // the copy-on-write itself doing the work, which is the one
    // property the fan-out caller's correctness rests on.
    std::fs::write(&dst, b"overwritten").unwrap();
    assert!(
        std::fs::read(&src).unwrap() == data,
        "the source moved under a clone"
    );

    // An empty source is a real case here (a zero-length FileDesc's
    // sibling), and clonefile/FICLONE both accept one.
    let esrc = dir.join("empty.bin");
    let edst = dir.join("empty-copy.bin");
    std::fs::write(&esrc, b"").unwrap();
    assert_eq!(copy_file_cow(&esrc, &edst).unwrap(), 0);
    assert!(edst.exists() && std::fs::metadata(&edst).unwrap().len() == 0);

    // A missing source is an error on both arms, never a silent empty
    // destination - the caller stats first, so reaching this means the
    // file vanished mid-settle.
    let gone = dir.join("nope.bin");
    assert!(copy_file_cow(&gone, &dir.join("nope-copy.bin")).is_err());

    std::fs::remove_dir_all(&dir).ok();
}

/// X5-06/08/19 OWED item 4 (31 Aug 2026): [`copy_file_cow`]'s
/// destination is BOUND on every arm, so the rule X5-07 had to spell a
/// second time at its own call site is now the one `relpath` already
/// spelled.
///
/// The defect being pinned is `std::fs::copy`'s, and it was measured
/// red once already: it FOLLOWS a symlink at its destination, so a
/// dangling link planted at the copy's name created the file it pointed
/// at - outside the job's output directory, under a log line saying the
/// bytes had been verified.
#[cfg(unix)]
#[test]
fn copy_file_cow_refuses_an_alias_at_its_destination() {
    let dir = std::env::temp_dir().join(format!("nzbfast-cowbind-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    let out = dir.join("out");
    let outside = dir.join("outside");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    let src = out.join("src.bin");
    std::fs::write(&src, b"payload").unwrap();

    // A DANGLING link at the destination's name. `Path::exists` answers
    // false for this and `std::fs::copy` wrote straight through it.
    let elsewhere = outside.join("elsewhere.bin");
    let dst = out.join("copy.bin");
    std::os::unix::fs::symlink(&elsewhere, &dst).unwrap();
    assert!(copy_file_cow(&src, &dst).is_err());
    assert!(
        !elsewhere.exists(),
        "the copy followed a dangling alias out of the output directory"
    );
    std::fs::remove_file(&dst).unwrap();

    // A live link at the destination, over a file that must not move.
    const SENTINEL: &[u8] = b"nothing in the job may touch this inode\n";
    let sentinel = outside.join("sentinel.bin");
    std::fs::write(&sentinel, SENTINEL).unwrap();
    std::os::unix::fs::symlink(&sentinel, &dst).unwrap();
    assert!(copy_file_cow(&src, &dst).is_err());
    assert_eq!(std::fs::read(&sentinel).unwrap(), SENTINEL);
    std::fs::remove_file(&dst).unwrap();

    // The PARENT swapped for a link, which is the X5-08 half.
    let deep = out.join("sub");
    std::fs::create_dir_all(&deep).unwrap();
    std::fs::remove_dir(&deep).unwrap();
    std::os::unix::fs::symlink(&outside, &deep).unwrap();
    let e = copy_file_cow(&src, &deep.join("copy.bin")).unwrap_err();
    assert!(
        e.to_string().contains("not a real directory"),
        "unexpected error: {e}"
    );
    assert!(!outside.join("copy.bin").exists());

    // And the documented contract - the destination must not exist - is
    // a MECHANISM now rather than a note to the caller.
    let taken = out.join("taken.bin");
    std::fs::write(&taken, b"somebody else's").unwrap();
    let e = copy_file_cow(&src, &taken).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists, "{e}");
    assert_eq!(std::fs::read(&taken).unwrap(), b"somebody else\'s");

    std::fs::remove_dir_all(&dir).ok();
}

/// `write_article_at` is the article-delivery door: it must stay silent
/// for a disjoint write and for a duplicate that agrees with what is
/// already there, and latch only when two deliveries CONTRADICT each
/// other. The three cases drive the method directly, so a change to the
/// peek, the read-back or the compare shows here rather than only at the
/// far end of an e2e run.
#[test]
fn write_article_at_latches_only_a_contradiction() {
    let dir = std::env::temp_dir().join(format!("nzbfast-artconf-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // (a) DISJOINT: the shape every well-formed post has. Nothing to
    // compare, nothing latched.
    let w = FileWriter::create(&dir.join("disjoint.bin"), 8).unwrap();
    w.write_article_at(0, b"abcd").unwrap();
    w.write_article_at(4, b"efgh").unwrap();
    assert!(
        !w.had_rewrite(),
        "disjoint article ranges are not a rewrite at all"
    );
    assert_eq!(
        w.conflicting_rewrite_span(),
        None,
        "a disjoint write must never latch a conflict"
    );

    // (b) IDENTICAL OVERLAP: a same-article hedge or tail duplicate
    // re-delivering bytes already on disk. `had_rewrite` sees it - that
    // is what forces the set-covered read-back - but it is harmless, so
    // the conflict latch must stay clear.
    let w = FileWriter::create(&dir.join("agree.bin"), 8).unwrap();
    w.write_article_at(0, b"abcdefgh").unwrap();
    w.write_article_at(2, b"cdef").unwrap();
    assert!(w.had_rewrite(), "the range really was written twice");
    assert_eq!(
        w.conflicting_rewrite_span(),
        None,
        "a duplicate that agrees with the bytes on disk is not a contradiction"
    );

    // (c) DIFFERING OVERLAP: two deliveries claim [2, 6) and disagree.
    // The span is latched by its FILE offset and length, which is what
    // lets the refusal name the bytes; and the write still happens, so
    // nothing about the existing on-disk behaviour moves.
    let path = dir.join("conflict.bin");
    let w = FileWriter::create(&path, 8).unwrap();
    w.write_article_at(0, b"abcdefgh").unwrap();
    w.write_article_at(2, b"ZZZZ").unwrap();
    assert!(
        w.had_conflicting_rewrite(),
        "two deliveries disagreeing about one range is exactly the conflict"
    );
    assert_eq!(
        w.conflicting_rewrite_span(),
        Some((2, 4)),
        "the latch names the contested range so settle can quote it"
    );
    let mut got = [0u8; 8];
    w.read_at(&mut got, 0).unwrap();
    assert_eq!(
        &got, b"abZZZZgh",
        "latching a conflict must not suppress the write - which copy lands is \
         settle's problem, and refusing here would only put it back on arrival order"
    );

    // A second, DIFFERENT contradiction does not move the record: the
    // first range is the one the refusal quotes.
    w.write_article_at(6, b"QQ").unwrap();
    assert_eq!(
        w.conflicting_rewrite_span(),
        Some((2, 4)),
        "the first contested range wins the record"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
