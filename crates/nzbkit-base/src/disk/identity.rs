//! When do two paths reach ONE file object? The destination VOLUME's own
//! case behaviour, and the inode identity behind a pair of names.
//!
//! Split out of `disk.rs` under the size gate (TODO 106) on 31 Aug 2026,
//! when that file was at 2,941 of the flat 3,000-line ceiling with 59
//! free and several lanes appending to it. This is one subject end to
//! end: every door here answers some form of "are these two names the
//! same file", and the two halves are not separable in practice - a
//! case-insensitive volume files `readme.nfo` and `README.nfo` as ONE
//! object from ONE stored entry, which is exactly the shape
//! [`is_redundant_link`] has to tell from a hardlink before it lets a
//! caller unlink a name.
//!
//! Three mechanisms, one question:
//!
//! * [`case_insensitive_dir`] PROBES the destination volume, because
//!   case sensitivity is a mount property and the build target gets
//!   both interesting cases wrong.
//! * [`file_object_id`] and [`same_file_object`] read the identity the
//!   kernel keeps - `(device, inode)` on unix, `(volume serial, file
//!   index)` on Windows - without following a final symlink.
//! * [`is_redundant_link`] is the one that licenses a DELETE, so it
//!   fails closed and asks the DIRECTORIES rather than the path
//!   resolver.
//!
//! The third leg of the same subject lives next door in
//! `disk/casefold.rs`: [`super::case_fold_key`] answers the question for
//! two NAMES rather than for two entries on disk, and callers gate it on
//! [`case_insensitive_dir`] here, never on the build target.

use super::relpath;
use std::io;
use std::path::Path;

/// Does this directory live on a case-insensitive filesystem?
///
/// Decided by PROBING, not by the build target. Case sensitivity is a
/// property of the destination VOLUME, and `cfg!(target_os)` gets both
/// interesting cases wrong: the Linux container/NAS build writing to a
/// CIFS/SMB share or an exFAT disk is case-INsensitive, and a macOS build
/// writing to a case-sensitive APFS volume is not. Guessing from the build
/// target means `README` and `readme` are treated as two output files on a
/// volume where they name one - and the second write truncates the first.
///
/// Probes the nearest EXISTING ancestor, so it still answers correctly when
/// the output directory has not been created yet (sensitivity is a mount
/// property, and an ancestor is on the same mount). A directory reached
/// through a SYMLINK is measured too - see [`probed_case_insensitive`],
/// which is where that has to be arranged. Falls back to the platform
/// default only if no probe can be written.
pub fn case_insensitive_dir(dir: &Path) -> bool {
    probed_case_insensitive(dir).unwrap_or(cfg!(any(target_os = "macos", target_os = "windows")))
}

/// The measuring half of [`case_insensitive_dir`]: `Some` when the
/// VOLUME answered, `None` when nothing could be written and the caller
/// has to guess.
///
/// Split out so a test can assert the answer was MEASURED rather than
/// guessed. That distinction is invisible from the `bool` alone: on this
/// fleet the guess happens to be right, so a directory that is never
/// probed at all returns exactly what a working probe returns, and a
/// test reading only the bool passes either way.
///
/// # Why the resolve, and why not at the probe
///
/// [`probe_case_insensitive`] writes its scratch name through
/// [`relpath::open_out_leaf`], which refuses a symlink at the leaf's
/// IMMEDIATE PARENT - and for a flat probe name that parent is `d`
/// itself. So `--out /some/link` (and every `repair --dir <link>`,
/// `rarfix` and unpack-tail caller that never went through
/// `get_with_progress`'s own resolve) probed nothing, answered `None`,
/// and silently took the `cfg!(target_os)` guess: a Linux container
/// writing to a CIFS share through a link scored the volume SENSITIVE
/// and let two spellings of one file claim two files, which is the
/// identity question [`super::case_fold_key`] exists to answer.
///
/// The fix is [`relpath::resolve_out_root`] HERE, one component, exactly
/// what `open_dir_nofollow` judges - never making the probe follow
/// links. X5-19 is why that open is `create_new` plus no-follow in the
/// first place, and a probe nobody asked for must not be the one door in
/// the tree that follows an alias.
fn probed_case_insensitive(dir: &Path) -> Option<bool> {
    let mut at = Some(dir);
    while let Some(d) = at {
        if d.is_dir() {
            return probe_case_insensitive(&relpath::resolve_out_root(d));
        }
        at = d.parent();
    }
    None
}

/// One probe: write a mixed-case name, then ask for it in lower case.
///
/// THE NAME MUST NOT BE PREDICTABLE AND THE OPEN MUST NOT TRUNCATE.
/// This was `File::create` on `.nzbfast-CaseProbe-<pid>-<seq>` off a
/// process-global counter, and `File::create` TRUNCATES: one prior
/// observation of a probe file gives the next name, so a capability
/// probe nobody asked for destroyed a pre-existing file at that name
/// and then deleted it (X5-19, confirmed 30 Aug 2026). A pid and a
/// counter are a concurrency tiebreak, never a secret.
///
/// So: an unpredictable suffix, `create_new` (which FAILS on a name
/// already taken rather than truncating it) plus the same no-follow
/// rule the payload opens use, and a bounded retry for the collision
/// that is now reported instead of silently overwritten. Only the inode
/// this call created is ever removed.
fn probe_case_insensitive(dir: &Path) -> Option<bool> {
    for _ in 0..8 {
        let tag = format!(".nzbfast-CaseProbe-{}", probe_nonce());
        let mixed = dir.join(&tag);
        // `create_new`: a name already in use is a collision to retry,
        // never a file to truncate.
        match relpath::open_out_leaf(&mixed, relpath::LeafOpen::CreateNew) {
            Ok(f) => drop(f),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(_) => return None,
        }
        // `tag` is deliberately mixed-case, so this differs ONLY in case.
        let lowered = dir.join(tag.to_lowercase());
        let insensitive = std::fs::metadata(&lowered).is_ok();
        // Only ever the entry this call made.
        let _ = std::fs::remove_file(&mixed);
        return Some(insensitive);
    }
    None
}

/// A per-call nonce for the case probe's scratch name: unpredictable
/// from the outside, and distinct within this process.
///
/// `RandomState` is the stdlib's own OS-seeded hasher state - the one
/// `HashMap` uses to make its iteration order unguessable - so this
/// needs no `rand` dependency and no hand-rolled entropy. Each
/// `RandomState::new()` takes the thread's seed and bumps it, so two
/// probes in one thread differ even before the counter below is mixed
/// in; the counter is the belt, because collision here is only a retry
/// and never a truncate.
///
/// It is deliberately NOT a CSPRNG and nothing here wants one: the
/// property required is that an onlooker who has seen one probe name
/// cannot derive the next, which is what the old pid-plus-counter
/// spelling failed at.
fn probe_nonce() -> String {
    use std::hash::BuildHasher as _;
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let h = std::collections::hash_map::RandomState::new().hash_one(seq);
    // Mixed case on purpose: the probe asks whether the lower-cased
    // spelling names the same file.
    format!("Aa{h:016x}")
}

/// Do these two paths name ONE file object, as the filesystem sees it?
///
/// X5-20 (codex Extreme Wave 5, 30 Aug 2026) is what this exists for:
/// renaming one hardlink over another name for the SAME inode is a POSIX
/// no-op that still returns `Ok(())`, so a caller that grades its rename
/// by that return value alone reports a publish it did not perform and
/// leaves the old name sitting beside the new one. A rename that changed
/// nothing is not a successful publish, and the only way to know is to
/// ask about identity rather than about the call's result.
///
/// Read WITHOUT following a final symlink, because what `rename` and
/// `remove_file` act on is the directory ENTRY: a symlink pointing at `b`
/// is a different object from `b`, and calling the two the same would
/// license unlinking a payload's only name.
///
/// Windows carries real hardlinks (`CreateHardLinkW` on NTFS), so this is
/// not a unix-only question. The identity there is the (volume serial,
/// file index) pair, which is a property of an OPEN handle rather than of
/// a path - hence the `OpenOptions`, with the reparse-point flag standing
/// in for `symlink_metadata`.
///
/// Anything that cannot be stat'd or opened answers `false`: an identity
/// nobody could establish must never license a delete.
///
/// The MECHANISM behind all three paragraphs above - the symlink-free
/// read, the Windows handle dance, and the `None` that a failed stat
/// answers with - lives in [`file_object_id`] since M4-61, because a
/// caller testing many paths against many others needs the value rather
/// than the comparison. This is that function twice; nothing about what
/// it decides moved with it.
pub fn same_file_object(a: &Path, b: &Path) -> bool {
    match (file_object_id(a), file_object_id(b)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

/// What [`same_file_object`] COMPARES, handed back so a caller with many
/// paths to test against many others can compare values instead of
/// paying two filesystem round trips per pair.
///
/// A machine-local, run-local handle: two paths name one file object
/// exactly when their ids are equal and both resolved. It is NOT stable
/// across reboots, remounts or machines, and it is not a checksum of the
/// bytes - do not persist it or compare it across processes.
///
/// Every judgement [`same_file_object`]'s own header makes applies here
/// unchanged, because that function is now this one twice: read WITHOUT
/// following a final symlink, since what `rename` and `remove_file` act
/// on is the directory ENTRY; and anything that cannot be stat'd or
/// opened answers `None`, because an identity nobody could establish
/// must never license a delete.
///
/// M4-61 is what made it worth exposing. `unpack::PublishedNames` asks
/// "is this candidate name already one of THIS job's files" once per
/// publish against every name the job has landed, and paying
/// `same_file_object` per pair made the publish pass quadratic in
/// syscalls - MEASURED on the 30 Aug 2026 dev box, a 1,000-file
/// re-download into a populated folder went from 124 ms to 1.73 s, and
/// the gap grows with the square. Recording the id once per landed file
/// turns the walk into an integer lookup.
///
/// The triple is a portable SHAPE, not a meaningful tuple: unix fills
/// `(device, inode, 0)` and Windows `(volume serial, file index high,
/// file index low)`. Nothing may read the fields individually.
pub fn file_object_id(p: &Path) -> Option<(u64, u64, u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::symlink_metadata(p).ok()?;
        Some((m.dev() as u64, m.ino(), 0))
    }
    #[cfg(windows)]
    {
        use std::fs::OpenOptions;
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;
        // NOT `std::os::windows::fs::MetadataExt`: its
        // `volume_serial_number` / `file_index` are behind the unstable
        // `windows_by_handle` feature (rust-lang#63010) and do not
        // compile on the pinned stable toolchain. Checked, not assumed -
        // the first cut of this used them and only the cross-target
        // clippy run said so, which is the SIXTEENTH gate's whole class.
        // So the same question is asked of kernel32 directly, the way
        // `hide_from_user` in the parent module already does.
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        const FILE_SHARE_ALL: u32 = 0x0000_0007;
        // Thirteen DWORDs, in the documented order, with no padding to
        // get wrong: attributes, three FILETIMEs, volume serial, size
        // hi/lo, link count, index hi/lo.
        // The seven fields this call never reads carry a leading
        // underscore so they read as LAYOUT rather than as dead code -
        // the struct has to be whole for the two indices to land at the
        // right offsets.
        #[repr(C)]
        #[derive(Default)]
        struct ByHandleFileInformation {
            _attributes: u32,
            _creation: [u32; 2],
            _last_access: [u32; 2],
            _last_write: [u32; 2],
            volume_serial: u32,
            _size_high: u32,
            _size_low: u32,
            _links: u32,
            index_high: u32,
            index_low: u32,
        }
        // SAFETY: the declaration must match the real kernel32 export;
        // this mirrors the documented Win32 signature
        // (GetFileInformationByHandle: HANDLE, LPBY_HANDLE_FILE_INFORMATION
        // -> BOOL), with the handle as the raw pointer std hands back.
        unsafe extern "system" {
            fn GetFileInformationByHandle(
                handle: *mut core::ffi::c_void,
                info: *mut ByHandleFileInformation,
            ) -> i32;
        }
        // OPEN_REPARSE_POINT keeps a symlink from resolving,
        // BACKUP_SEMANTICS lets a directory open at all, and an access
        // mask of 0 asks for metadata rights only - so this neither
        // reads the file nor blocks anyone writing it.
        let f = OpenOptions::new()
            .access_mode(0)
            .share_mode(FILE_SHARE_ALL)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(p)
            .ok()?;
        let mut info = ByHandleFileInformation::default();
        // SAFETY: `f` is open for the whole call, so its handle is
        // valid; `info` is a live, correctly typed, correctly sized
        // out-parameter that outlives the call. Its fields are read
        // only when the call reports success.
        let ok = unsafe { GetFileInformationByHandle(f.as_raw_handle(), &mut info) };
        if ok == 0 {
            return None;
        }
        Some((
            u64::from(info.volume_serial),
            u64::from(info.index_high),
            u64::from(info.index_low),
        ))
    }
    #[cfg(not(any(unix, windows)))]
    {
        // No portable identity to establish, and a guess here is a delete.
        let _ = p;
        None
    }
}

/// Is `alias` a directory entry of its OWN that names the same file
/// object as `canonical` - a redundant SECOND name for one inode, rather
/// than one entry reached by two spellings?
///
/// The caller's question is "may I unlink `alias` and still have the
/// bytes at `canonical`", so both halves have to hold: same object, and
/// two distinct entries.
pub fn is_redundant_link(alias: &Path, canonical: &Path) -> bool {
    if alias == canonical || !same_file_object(alias, canonical) {
        return false;
    }
    // Ask the DIRECTORIES rather than the path resolver, and that is the
    // whole reason this is not a two-stat function. A case-insensitive
    // volume answers `readme.nfo` and `README.nfo` with one inode from
    // ONE stored entry, so the identity test above cannot tell that
    // shape from a hardlink - and unlinking `alias` there destroys the
    // file's only name. A STORED name is exact, so requiring both
    // spellings to appear in their own listing separates the two.
    stored_entry(alias) && stored_entry(canonical)
}

/// Does `p`'s own directory list an entry spelled EXACTLY `p`'s file
/// name? `Path::exists` cannot answer this: it goes through the volume's
/// lookup, which folds case on macOS and Windows.
fn stored_entry(p: &Path) -> bool {
    let Some(name) = p.file_name() else {
        return false;
    };
    let dir = match p.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let Ok(rd) = std::fs::read_dir(dir) else {
        return false;
    };
    rd.flatten().any(|e| e.file_name() == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The probe must agree with what the filesystem ACTUALLY does, on
    /// whatever volume the suite happens to run on. That is the whole point
    /// of probing instead of reading `cfg!(target_os)`: this assertion is
    /// meaningful on case-sensitive Linux CI, on a case-insensitive macOS
    /// dev box, and on a Linux runner whose tmp is a case-insensitive mount -
    /// where the old build-target guess was simply wrong.
    #[test]
    fn case_probe_agrees_with_the_real_filesystem() {
        let dir = std::env::temp_dir().join(format!("nzbfast-case-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // Ground truth: write one spelling, ask for the other.
        std::fs::write(dir.join("Ground.txt"), b"x").unwrap();
        let truth = std::fs::metadata(dir.join("ground.txt")).is_ok();

        assert_eq!(
            case_insensitive_dir(&dir),
            truth,
            "probe disagrees with the filesystem at {}",
            dir.display()
        );

        // A not-yet-created output dir must still answer correctly: the
        // probe walks up to the nearest existing ancestor, since case
        // sensitivity is a property of the mount.
        let unborn = dir.join("does").join("not").join("exist");
        assert_eq!(case_insensitive_dir(&unborn), truth);

        // The probe must not leave its scratch file behind.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains("CaseProbe") || n.contains("caseprobe"))
            .collect();
        assert!(leftovers.is_empty(), "probe left {leftovers:?} behind");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// X5-20's identity primitive, driven directly: the three answers
    /// [`is_redundant_link`] has to get right, plus the two that license a
    /// delete and so must fail closed.
    ///
    /// The middle one is the reason this is not a pair of `stat` calls. On a
    /// case-insensitive volume `readme.nfo` and `README.nfo` are ONE stored
    /// entry reached by two spellings, so the inode pair matches exactly as
    /// it does for a hardlink - and the caller unlinks. Whether this host
    /// folds case is probed rather than assumed, so the assertion holds on
    /// either kind of volume.
    #[test]
    fn a_redundant_link_is_a_second_entry_and_never_a_second_spelling() {
        let dir = std::env::temp_dir().join(format!("nzbfast-redundant-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let a = dir.join("payload.bin");
        std::fs::write(&a, b"bytes").unwrap();

        // A file is not a redundant link to itself: unlinking it is the
        // payload gone.
        assert!(!is_redundant_link(&a, &a));
        assert!(same_file_object(&a, &a));

        // Two independent files are two objects.
        let b = dir.join("other.bin");
        std::fs::write(&b, b"bytes").unwrap();
        assert!(!same_file_object(&a, &b));
        assert!(!is_redundant_link(&a, &b));

        // A second NAME for one inode is the thing being looked for, and
        // this arm runs on WINDOWS too since 31 Aug 2026. Until then it was
        // `#[cfg(unix)]`, so the kernel32 `GetFileInformationByHandle`
        // identity - the (volume serial, file index) pair `file_object_id`
        // asks for - had never once been asked about an actual alias on any
        // Windows box, on a fleet where no box can run that arm. The other
        // inputs here (same path, distinct files, a case variant) do drive
        // the FFI, so what was missing was specifically the case it has to
        // get RIGHT rather than the code path.
        //
        // ATTEMPT-AND-SKIP, not an unconditional lift: a hardlink needs
        // NTFS and nothing verifies a runner's temp volume is one, so a
        // bare `unwrap` here could redden `windows-unit` for an
        // environmental reason rather than a real one. On unix it stays a
        // hard requirement, which is what it has always been - loosening
        // that would trade away coverage this test already had. The skip
        // PRINTS, so an arm that has quietly stopped running shows in the
        // log instead of reading as a pass.
        {
            let link = dir.join("alias.bin");
            match std::fs::hard_link(&a, &link) {
                Ok(()) => {
                    assert!(same_file_object(&a, &link));
                    assert!(is_redundant_link(&link, &a));
                    // ...and it is symmetric: neither name is privileged.
                    assert!(is_redundant_link(&a, &link));
                    std::fs::remove_file(&link).unwrap();
                    // The bytes survive their second name going away -
                    // which is the whole property the caller unlinks on.
                    assert_eq!(std::fs::read(&a).unwrap(), b"bytes");
                }
                Err(e) => {
                    if cfg!(unix) {
                        panic!("hard_link must work on a unix temp volume: {e}");
                    }
                    eprintln!(
                        "[disk] SKIPPED the hardlink arm of the identity test: this \
                         volume does not support hard links ({e})."
                    );
                }
            }
        }

        // A case variant. On a folding volume it is the SAME object by
        // every stat, and still must not be called a redundant link.
        let variant = dir.join("PAYLOAD.BIN");
        if case_insensitive_dir(&dir) {
            assert!(same_file_object(&a, &variant));
        }
        assert!(!is_redundant_link(&variant, &a));
        assert!(!is_redundant_link(&a, &variant));

        // An identity nobody can establish never licenses a delete.
        let gone = dir.join("nope.bin");
        assert!(!same_file_object(&a, &gone));
        assert!(!is_redundant_link(&gone, &a));
        assert!(!is_redundant_link(&a, &gone));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The third instance of the X5 no-follow regression, at a door
    /// `resolve_out_root` at job start does not reach: the CASE PROBE.
    ///
    /// [`super::probe_case_insensitive`] writes its scratch name through
    /// [`crate::disk::open_out_leaf`], which refuses a symlink at the
    /// leaf's immediate PARENT - and for a flat probe name that parent IS
    /// the directory being probed. So a directory reached through a link
    /// answered `None` and [`case_insensitive_dir`] silently fell through to
    /// `cfg!(any(target_os = "macos", target_os = "windows"))`: a
    /// compile-time GUESS standing in for a volume measurement, at
    /// `par2repair`'s two sites, `par2repair::adopt` (the `repair` / `verify`
    /// CLI's own `--dir`), `rarfix` and the unpack tail's
    /// `unpack::published_names`, none of which go through
    /// `get_with_progress`'s resolve.
    ///
    /// WHY THIS ASSERTS ON `Some` RATHER THAN ON THE BOOL, and it is the
    /// whole reason the defect survived: on this fleet the guess is RIGHT.
    /// The unfixed fixture reads `real=true link=true` - exactly what a
    /// working probe prints - so a test that reads only
    /// [`case_insensitive_dir`] cannot fail here however wrong the code is,
    /// and a pin that cannot fail on the fleet that runs it is not a pin.
    /// What is falsifiable everywhere is whether the volume was ASKED, which
    /// is what [`super::probed_case_insensitive`] reports and what reverting
    /// the resolve turns back into `None`.
    ///
    /// The cost of the guess is a wrong [`crate::disk::case_fold_key`] gate:
    /// scored
    /// sensitive on an insensitive volume, two spellings claim two files
    /// that are one and the second publish renames over the first (M4-61);
    /// scored insensitive on a case-sensitive volume, two real files
    /// collapse onto one name.
    #[cfg(unix)]
    #[test]
    fn the_case_probe_measures_a_directory_reached_through_a_link() {
        let base = std::env::temp_dir().join(format!("nzbfast-caselink-{}", std::process::id()));
        std::fs::remove_dir_all(&base).ok();
        let real = base.join("real");
        std::fs::create_dir_all(&real).unwrap();
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        // The control: an ordinary directory has always been measured, so a
        // `None` here would mean the probe is broken outright rather than
        // blind to links, and every assertion below would be vacuous.
        let direct = super::probed_case_insensitive(&real)
            .expect("an ordinary directory must be measured, not guessed");

        assert_eq!(
            super::probed_case_insensitive(&link),
            Some(direct),
            "the volume was never asked about {} - the answer callers get is \
             the cfg!(target_os) guess, which is right on this box by \
             coincidence and wrong for a container writing to a CIFS share",
            link.display()
        );

        // An output directory that does not exist yet, under the link: the
        // walk stops at the nearest existing ancestor, which is the link
        // itself, so this is the same defect reached the way a job reaches
        // it - `--out <link>/job` before the job directory is made.
        assert_eq!(
            super::probed_case_insensitive(&link.join("job").join("sub")),
            Some(direct),
            "an unborn output directory under a link must still be measured"
        );

        // And the public door agrees, so the split above cannot drift from
        // what every caller actually reads.
        assert_eq!(case_insensitive_dir(&link), direct);

        // The probe cleans up after itself on the resolved path too: a
        // scratch file left in the target is a file the user did not ask for.
        let left: Vec<_> = std::fs::read_dir(&real)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.to_lowercase().contains("caseprobe"))
            .collect();
        assert!(left.is_empty(), "probe left {left:?} behind");

        std::fs::remove_dir_all(&base).ok();
    }
}
