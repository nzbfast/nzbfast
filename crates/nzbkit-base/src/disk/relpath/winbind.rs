//! The Windows half of [`super::open_out_leaf`]'s two refusals: open the
//! leaf's PARENT as a directory HANDLE, then create the leaf RELATIVE to
//! that handle, so the directory that was checked is the directory
//! written into.
//!
//! # Why this file exists at all
//!
//! Until 31 Aug 2026 the two refusals were not the same strength. The
//! LEAF was bound - the open carries `FILE_FLAG_OPEN_REPARSE_POINT`, so a
//! link planted after the check is OPENED rather than followed and the
//! refusal is made against the HANDLE - while the PARENT was a
//! `symlink_metadata` by NAME immediately before the open, with the
//! window after it wide open. Win32 has no `openat`; `NtCreateFile` does,
//! through `RootDirectory` in `OBJECT_ATTRIBUTES` plus a relative
//! `UNICODE_STRING` name, and that is the whole of what this file is for.
//!
//! MEASURED on a native x86_64 Windows 11 machine over NTFS, 31 Aug 2026
//! (no rustc version is cited because none of this is the compiler's
//! behaviour - every fact below is the kernel's answer to a syscall),
//! and it is a DEMONSTRATION rather than a reasoned exposure, which is
//! what makes this a fix and not a hardening on principle: with a directory handle already open, its name was
//! renamed away and a directory symlink to `outside` put back at the old
//! name. Creating the leaf RELATIVE to the handle landed it in the
//! ORIGINAL directory and left `outside` empty. The by-NAME open beside
//! it - which is exactly what this arm did before - LEAKED the file into
//! `outside`. Both in one run, so the window is demonstrated and closed
//! by the same probe.
//!
//! # In its own file rather than inline in `relpath.rs`
//!
//! That file sits within a few dozen lines of its size-gate ceiling and
//! several lanes append to it; this is FFI plus the measurements that
//! make the FFI checkable, plus its own cases. Moving the arm here takes `relpath.rs`
//! DOWN rather than up. Same reasoning as `relpath/seam.rs` next door.
//!
//! # What is still resolved by NAME here, said rather than implied
//!
//! Only the leaf's IMMEDIATE parent is bound. A symlink ABOVE it
//! (`C:\users` -> elsewhere, a linked volume) is followed exactly as
//! before, which is the module's stated hold-out on unix too - unix's
//! `open_leaf_in` is `open_dir_nofollow` on the parent plus one
//! `openat`, and this is now the same two steps. What the unix side has
//! and this does not is [`super::open_out_leaf_under`]'s WHOLE-WALK
//! bind (`walk_out_dirs`, one bound descriptor per component) and
//! `renameat`; on Windows those two still resolve by path. They are
//! their own items and are not made here.

use std::ffi::{OsStr, c_void};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
use std::path::Path;

use super::{LeafOpen, leaf_is_a_link, not_a_real_dir};

type Ntstatus = i32;
type Handle = *mut c_void;

/// A counted, NOT necessarily NUL-terminated UTF-16 string. `length` and
/// `maximum_length` are in BYTES and exclude any terminator - the single
/// easiest field in this file to get wrong, because every other Windows
/// string API counts characters.
#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

/// `RootDirectory` is what makes this `openat`: with it set, `ObjectName`
/// is resolved INSIDE that handle's object rather than against the
/// namespace, so a name swapped at the parent after the handle was opened
/// cannot reach the write.
#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: Handle,
    object_name: *const UnicodeString,
    attributes: u32,
    security_descriptor: *mut c_void,
    security_qos: *mut c_void,
}

/// The `Status`/`Pointer` union is pointer-sized, so one `usize` gives
/// this struct the right size and alignment on both 32- and 64-bit. We
/// never read it: `NtCreateFile`'s own return value carries the status.
#[repr(C)]
struct IoStatusBlock {
    status_or_pointer: usize,
    information: usize,
}

// SAFETY: the declarations must match ntdll's real exports. These mirror
// the documented NT signatures - `NtCreateFile` takes an out-handle, an
// access mask, pointers to OBJECT_ATTRIBUTES and IO_STATUS_BLOCK, an
// optional allocation size, four ULONGs and an optional EA buffer, and
// returns NTSTATUS; `RtlNtStatusToDosError` maps NTSTATUS to a Win32
// error code. Neither writes through any pointer this file does not own.
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtCreateFile(
        file_handle: *mut Handle,
        desired_access: u32,
        object_attributes: *const ObjectAttributes,
        io_status_block: *mut IoStatusBlock,
        allocation_size: *mut i64,
        file_attributes: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        ea_buffer: *mut c_void,
        ea_length: u32,
    ) -> Ntstatus;
    fn RtlNtStatusToDosError(status: Ntstatus) -> u32;
}

/// Open the DIRECTORY itself rather than a file inside it.
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
/// Hand back the reparse point rather than resolving through it. On the
/// parent this is what lets the check below see a link at all; on the
/// leaf it is what binds the refusal to an object instead of to a name.
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

/// `SYNCHRONIZE | FILE_TRAVERSE | FILE_READ_ATTRIBUTES` - the least that
/// serves as an `NtCreateFile` `RootDirectory` and still answers
/// `metadata()`. Deliberately NOT `GENERIC_READ`: that additionally asks
/// for `FILE_LIST_DIRECTORY`, which a directory can be ACL'd to withhold
/// from someone who may still create files in it, and this arm must not
/// newly refuse a write the old one allowed.
const DIR_ACCESS: u32 = 0x0010_0000 | 0x0000_0020 | 0x0000_0080;
/// `FILE_GENERIC_READ | FILE_GENERIC_WRITE`, which is what
/// `OpenOptions::new().read(true).write(true)` asks for, plus the
/// `SYNCHRONIZE` both already carry.
const LEAF_ACCESS: u32 = 0x0012_019F;
/// `SYNCHRONIZE | FILE_READ_ATTRIBUTES`: enough to ask what is at a name.
const PEEK_ACCESS: u32 = 0x0010_0000 | 0x0000_0080;
/// `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`, matching
/// what std's own `File::open` asks for - so holding the parent handle
/// for the length of one leaf open blocks nothing, deletion included.
const SHARE_ALL: u32 = 0x0000_0007;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
/// Win32 sets this for every path it resolves; without it the leaf would
/// match case-sensitively while every other door in the process does not.
const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;

/// A synchronous handle - the file position lives in the kernel and
/// `ReadFile`/`WriteFile` need no OVERLAPPED. This is what std's own
/// `File` is, and asking for it is what makes the handle below usable as
/// an ordinary `std::fs::File`.
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
/// A payload leaf is never a directory. This is `O_RDWR`'s `EISDIR` on
/// the other platform, asked for up front.
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

const FILE_OPEN: u32 = 1;
const FILE_CREATE: u32 = 2;
const FILE_OPEN_IF: u32 = 3;

/// One `NtCreateFile`, relative to `dir`.
///
/// `dir` names an object, not a name, so a swap landing after it was
/// opened cannot reach this call. Errors come back as ordinary
/// [`io::Error`]s through `RtlNtStatusToDosError`, which is the same
/// mapping the Win32 layer applies - MEASURED so the callers that read
/// `ErrorKind` keep working: `STATUS_OBJECT_NAME_COLLISION` arrives as
/// `AlreadyExists` (which `disk::probe_case_insensitive` retries on) and
/// `STATUS_OBJECT_NAME_NOT_FOUND` as `NotFound` (which
/// [`LeafOpen::Existing`] exists to report).
fn create_at(
    dir: &File,
    leaf: &OsStr,
    disposition: u32,
    access: u32,
    options: u32,
) -> io::Result<File> {
    let mut name: Vec<u16> = leaf.encode_wide().collect();
    // `length` is a byte count in a u16. A path component cannot reach
    // 32,767 UTF-16 units on any Windows filesystem, so this is a
    // refusal rather than a case to handle - but it is CHECKED, because
    // a silent wrap would hand the kernel a truncated name.
    let Ok(bytes) = u16::try_from(name.len().saturating_mul(2)) else {
        return Err(io::Error::other(
            "refusing to open output: the file name is too long to name",
        ));
    };
    let counted = UnicodeString {
        length: bytes,
        maximum_length: bytes,
        buffer: name.as_mut_ptr(),
    };
    let attrs = ObjectAttributes {
        length: size_of::<ObjectAttributes>() as u32,
        root_directory: dir.as_raw_handle().cast(),
        object_name: &counted,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: std::ptr::null_mut(),
        security_qos: std::ptr::null_mut(),
    };
    let mut handle: Handle = std::ptr::null_mut();
    let mut iosb = IoStatusBlock {
        status_or_pointer: 0,
        information: 0,
    };
    // SAFETY: `handle` and `iosb` are live locals written by the call and
    // nothing else aliases them. `attrs` outlives the call and points at
    // `counted`, which points at `name`'s buffer - both locals of this
    // frame, and `name` is not moved or reallocated between here and the
    // return. The root directory is the live handle of `dir`, which the
    // caller keeps open across the call. The remaining arguments are
    // integers, and the two optional pointers are passed null, which the
    // documented signature permits.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access,
            &attrs,
            &mut iosb,
            std::ptr::null_mut(),
            FILE_ATTRIBUTE_NORMAL,
            SHARE_ALL,
            disposition,
            options,
            std::ptr::null_mut(),
            0,
        )
    };
    if status < 0 {
        // SAFETY: a pure integer-to-integer mapping in ntdll; it reads
        // and writes no memory.
        let dos = unsafe { RtlNtStatusToDosError(status) };
        return Err(io::Error::from_raw_os_error(dos as i32));
    }
    // SAFETY: `handle` is a fresh, owned handle from the call above
    // (which reported success), and nothing else holds or closes it - so
    // `File` takes sole ownership of it exactly once.
    Ok(unsafe { File::from_raw_handle(handle) })
}

/// The parent directory of an output leaf, opened by NAME but refusing a
/// symlink at that name - the Windows twin of unix's `O_DIRECTORY |
/// O_NOFOLLOW`.
///
/// The refusal is made against the HANDLE and not against a stat, so it
/// is bound the same way the leaf's is: `FILE_FLAG_OPEN_REPARSE_POINT`
/// hands back the reparse point itself, and `is_symlink()` is then a
/// question about the object this call is holding. MEASURED on the box:
/// a real directory reads `(is_dir, is_symlink) = (true, false)` and a
/// directory symlink reads `(false, true)`, so both halves of the test
/// below are load-bearing rather than one belt and one brace.
///
/// `is_symlink()` and NOT the raw `FILE_ATTRIBUTE_REPARSE_POINT` bit,
/// for the reason [`open_leaf_at`] states at length for the leaf: a
/// OneDrive placeholder or a deduplication stub is a reparse point that
/// redirects nothing, and refusing those would refuse an ordinary
/// download into a synced folder.
pub(super) fn open_dir_nofollow(parent: &Path) -> io::Result<File> {
    let dir = OpenOptions::new()
        .access_mode(DIR_ACCESS)
        .share_mode(SHARE_ALL)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(parent)?;
    let meta = dir.metadata()?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(not_a_real_dir(parent));
    }
    Ok(dir)
}

/// Open the payload leaf INSIDE an already-bound directory.
///
/// `shown` is only ever used to spell a refusal - resolving a handle back
/// to a path is neither portable nor honest, and these refusals are read
/// by people rather than parsed.
///
/// THE DISPOSITIONS ARE NON-DESTRUCTIVE ON PURPOSE, and this is the one
/// judgement in the file that reading the Win32 documentation will not
/// give you. `Truncate` is `FILE_OPEN_IF` plus an explicit `set_len(0)`
/// AFTER the handle has been judged, never `FILE_OVERWRITE_IF`.
/// MEASURED on the box, all four dispositions against a planted file
/// symlink: `FILE_OPEN_IF` and `FILE_OPEN` hand back the LINK
/// (`is_symlink()` true, link and outside target both intact), so the
/// refusal below fires; `FILE_CREATE` reports `AlreadyExists` and
/// touches nothing; but `FILE_OVERWRITE_IF` REPLACES the reparse point
/// with a fresh empty file, so the handle it returns reads
/// `is_symlink() == false` and the refusal never fires. Its outside
/// target survives either way, so that spelling is not a data-loss bug -
/// it silently DESTROYS the user's link instead of refusing it, and it
/// blinds the one test that closes the window. Do not "simplify" this
/// back to `OpenOptions::truncate(true)`.
///
/// ONE GUARD, NOT TWO, AND THAT IS THE POINT. The refusal is the HANDLE
/// test after the open, and nothing runs in front of it on the path that
/// succeeds. An earlier cut of this file also peeked at the name BEFORE
/// opening - a bound `FILE_OPEN` replacing the `symlink_metadata` this
/// arm used to do - and it was deleted for a reason worth keeping
/// written down: MUTATION FOUND IT. With the peek in front, swapping
/// `Truncate` back to `FILE_OVERWRITE_IF` broke nothing, because the
/// peek refused the planted link before the destructive open could be
/// reached. Two guards, either of them sufficient, make BOTH
/// unfalsifiable - so the test that exists to pin the disposition was
/// passing for the wrong reason. The peek now runs ONLY on the error
/// path, where the open has already refused and cannot say what it
/// refused (see [`peek_is_a_link`]), so it can no longer stand in for
/// the guard that matters. It is also one syscall cheaper on every
/// successful open than the `symlink_metadata` it replaced.
///
/// A link planted between the check and the open is therefore refused by
/// the open ITSELF: it is handed back as the reparse point, and the test
/// below is a question about that object rather than about a name.
///
/// `is_symlink()` and NOT the raw `FILE_ATTRIBUTE_REPARSE_POINT` bit,
/// which is the precision of this arm rather than a shorthand for it.
/// std reports it off the handle's own reparse TAG, so it is true for
/// the REDIRECTING tags and false otherwise. MEASURED: a file symlink
/// (`IO_REPARSE_TAG_SYMLINK`, 0xa000000c), a directory symlink (the same
/// tag) and a junction (`IO_REPARSE_TAG_MOUNT_POINT`, 0xa0000003) all
/// read true, while a plain file and a HARDLINK read false - the
/// hardlink deliberately so, since it is not a reparse point at all and
/// refusing it would depart from what `O_NOFOLLOW` does on unix. By tag
/// CLASSIFICATION rather than by measurement (these were reasoned, not
/// planted): a OneDrive Files On-Demand placeholder, a Server
/// data-deduplication stub and a WOF-compressed file are ALSO reparse
/// points and none carries the name-surrogate bit those two tags do, so
/// they stay writable. Refusing on the bare bit would break an ordinary
/// re-download over an existing file in a synced folder, which is a far
/// commoner shape than the attack this arm is for.
///
/// `journal.rs`'s `open_private_leaf` is the same flag with a
/// DELIBERATELY STRICTER predicate - it refuses the bare
/// `FILE_ATTRIBUTE_REPARSE_POINT` bit - and the two must NOT be
/// collapsed into one spelling. That file is nzbfast's own control file
/// inside its own spool, so "anything unusual at this name" is the right
/// question there. THIS path is the user's chosen output directory,
/// which on Windows is very often inside OneDrive. Two questions, not
/// two spellings of one.
pub(super) fn open_leaf_at(
    dir: &File,
    shown: &Path,
    leaf: &OsStr,
    mode: LeafOpen,
) -> io::Result<File> {
    let disposition = match mode {
        // Both CREATE a missing leaf and neither destroys one that is
        // there; `Truncate` empties it below, once the handle is judged.
        LeafOpen::Truncate | LeafOpen::Keep => FILE_OPEN_IF,
        LeafOpen::CreateNew => FILE_CREATE,
        // A missing file is the `NotFound` this mode exists to report
        // rather than an empty one nobody asked for.
        LeafOpen::Existing => FILE_OPEN,
    };
    let file = match create_at(
        dir,
        leaf,
        disposition,
        LEAF_ACCESS,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
    ) {
        Ok(file) => file,
        // The open REFUSED, and its own status cannot say what is in the
        // way - `FILE_CREATE` reports a taken name as
        // `AlreadyExists` whether the thing there is a file or a link,
        // and `FILE_NON_DIRECTORY_FILE` reports a directory symlink as
        // `STATUS_FILE_IS_A_DIRECTORY`. Only here, on a path that has
        // already failed, is the bound directory asked what the name
        // holds, so the refusal names the alias instead of the symptom.
        Err(e) => {
            return Err(if peek_is_a_link(dir, leaf) {
                leaf_is_a_link(shown)
            } else {
                e
            });
        }
    };
    if file.metadata()?.file_type().is_symlink() {
        return Err(leaf_is_a_link(shown));
    }
    if matches!(mode, LeafOpen::Truncate) {
        file.set_len(0)?;
    }
    Ok(file)
}

/// Is there a REDIRECTING reparse point at `leaf` inside `dir`?
///
/// Only ever asked on a path that has already failed, to turn a symptom
/// into a name. It answers `false` for anything it cannot open, which is
/// the conservative direction: the caller then reports the real error
/// rather than inventing an alias that may not be there.
///
/// It takes no `FILE_NON_DIRECTORY_FILE`, deliberately - a DIRECTORY
/// symlink is one of the two shapes it exists to name, so refusing to
/// open a directory would blind it to half its job.
fn peek_is_a_link(dir: &File, leaf: &OsStr) -> bool {
    create_at(
        dir,
        leaf,
        FILE_OPEN,
        PEEK_ACCESS,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
    )
    .is_ok_and(|f| f.metadata().is_ok_and(|m| m.file_type().is_symlink()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Local rather than reached from `relpath.rs`'s own test module:
    /// that one is `relpath::tests`, and this is `relpath::winbind::tests`
    /// - a sibling, not a descendant, so its private helpers are out of
    /// scope. Eight lines is cheaper than making one of them `pub`.
    fn scratch(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "nzbfast-winbind-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::remove_dir_all(&root).ok();
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    /// ATTEMPT-AND-SKIP, and the skip PRINTS. Planting a symlink needs
    /// SeCreateSymbolicLinkPrivilege (an administrator, or Developer
    /// Mode), which nothing here can promise about a runner - an
    /// unconditional lift would redden `windows-unit` for an
    /// environmental reason rather than a real one. A skipped arm that
    /// says nothing reads exactly like a pass, which is the failure this
    /// whole file exists to refuse one level down.
    fn plant_dir_link(target: &Path, at: &Path, arm: &str) -> bool {
        match std::os::windows::fs::symlink_dir(target, at) {
            Ok(()) => true,
            Err(e) => {
                eprintln!(
                    "[winbind] SKIPPED {arm}: this box cannot create a directory \
                     symlink ({e}). It needs SeCreateSymbolicLinkPrivilege."
                );
                false
            }
        }
    }

    /// THE POINT OF THE WHOLE FILE: the leaf is created inside the
    /// directory that was CHECKED, not the directory that name resolves
    /// to now.
    ///
    /// The parent handle is taken first, exactly as [`open_leaf_in`]
    /// takes it, and the swap is then performed while it is held - which
    /// is a race this test does not have to win, because the whole
    /// mechanism is that after the handle exists the name no longer
    /// matters. A threaded version would be flaky and would prove less.
    ///
    /// THE CONTROL IS NOT DECORATION. It performs the by-NAME open this
    /// arm used to do, in the same swapped state, and asserts it DOES
    /// leak into the outside directory. Without it a green here would be
    /// satisfied by a filesystem that never followed the link at all,
    /// and the test would pin nothing. Both halves measured together on
    /// a real box, 31 Aug 2026.
    #[test]
    fn the_leaf_lands_in_the_directory_that_was_checked_not_the_one_swapped_in() {
        let root = scratch("bind");
        let out = root.join("out");
        let outside = root.join("outside");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::create_dir_all(&outside).unwrap();

        // Bound BEFORE the swap, which is the whole mechanism.
        let dir = open_dir_nofollow(&out).unwrap();

        let real = root.join("out-real");
        std::fs::rename(&out, &real).expect("a held directory handle must not block a rename");
        if !plant_dir_link(&outside, &out, "the parent-bind arm") {
            std::fs::remove_dir_all(&root).ok();
            return;
        }

        let shown = out.join("payload.bin");
        let f = open_leaf_at(&dir, &shown, OsStr::new("payload.bin"), LeafOpen::Truncate)
            .expect("the bound create must succeed");
        drop(f);
        assert!(
            real.join("payload.bin").is_file(),
            "the write did not land in the directory the handle named"
        );
        assert!(
            !outside.join("payload.bin").exists(),
            "the write followed a parent swapped after it was bound"
        );

        // The control: what this replaced, in the same swapped state.
        drop(File::create(out.join("byname.bin")).unwrap());
        assert!(
            outside.join("byname.bin").is_file(),
            "the by-name control did not leak, so this test proves nothing \
             about the bind - the swap did not take effect"
        );

        std::fs::remove_file(&out).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    /// The handle-based parent refusal, which is the non-racing half of
    /// the same rule: a directory symlink at the parent's own name is
    /// refused rather than followed, and a real directory is not.
    ///
    /// Both halves are asserted because the test in
    /// [`open_dir_nofollow`] is two clauses and a one-sided case would
    /// pass with either of them deleted. MEASURED on the box: a real
    /// directory reads `(is_dir, is_symlink) = (true, false)` through
    /// `FILE_FLAG_OPEN_REPARSE_POINT` and a directory symlink reads
    /// `(false, true)`.
    #[test]
    fn a_link_at_the_parents_own_name_is_refused_and_a_real_directory_is_not() {
        let root = scratch("parent");
        let real = root.join("real");
        std::fs::create_dir_all(&real).unwrap();
        assert!(open_dir_nofollow(&real).is_ok());
        // A plain FILE is not a directory either - `BACKUP_SEMANTICS`
        // opens one happily, so the `is_dir` clause is what refuses it.
        let plain = root.join("plain.bin");
        std::fs::write(&plain, b"x").unwrap();
        let e = open_dir_nofollow(&plain).unwrap_err();
        assert!(
            e.to_string().contains("not a real directory"),
            "unexpected error: {e}"
        );

        let link = root.join("link");
        if plant_dir_link(&real, &link, "the parent-refusal arm") {
            let e = open_dir_nofollow(&link).unwrap_err();
            assert!(
                e.to_string().contains("not a real directory"),
                "unexpected error: {e}"
            );
        }
        std::fs::remove_file(&link).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    /// `Truncate` MUST NOT be `FILE_OVERWRITE_IF`, and this is the case
    /// that says so.
    ///
    /// MEASURED on the box: `FILE_OVERWRITE_IF` on a planted symlink
    /// REPLACES the reparse point with a fresh empty file, so the handle
    /// it hands back reads `is_symlink() == false`, the refusal below
    /// never fires, and the user's link is silently destroyed. The
    /// outside target survives either way - which is exactly why a test
    /// that only checked the sentinel would not catch the swap. So this
    /// asserts the refusal AND that the link is still a link afterwards.
    #[test]
    fn truncate_refuses_a_planted_link_without_destroying_it() {
        const SENTINEL: &[u8] = b"nothing in the job may touch this inode\n";
        let root = scratch("nodestroy");
        let out = root.join("out");
        let outside = root.join("outside");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let sentinel = outside.join("sentinel.bin");
        std::fs::write(&sentinel, SENTINEL).unwrap();

        let leaf = out.join("payload.bin");
        if std::os::windows::fs::symlink_file(&sentinel, &leaf).is_err() {
            eprintln!(
                "[winbind] SKIPPED the non-destructive arm: this box cannot \
                 create a file symlink. It needs SeCreateSymbolicLinkPrivilege."
            );
            std::fs::remove_dir_all(&root).ok();
            return;
        }
        let dir = open_dir_nofollow(&out).unwrap();
        for mode in [
            LeafOpen::Truncate,
            LeafOpen::Keep,
            LeafOpen::CreateNew,
            LeafOpen::Existing,
        ] {
            let e = open_leaf_at(&dir, &leaf, OsStr::new("payload.bin"), mode)
                .err()
                .unwrap_or_else(|| panic!("{mode:?} opened a planted symlink"));
            // THE MESSAGE AND NOT MERELY `is_err`. `CreateNew` reaches
            // this refusal through the ERROR-PATH peek rather than
            // through the handle test - `FILE_CREATE` on a taken name is
            // `AlreadyExists` whatever is there - so an `is_err`
            // assertion would be satisfied by the bare collision and the
            // peek would be pinned by nothing.
            assert!(
                e.to_string().contains("an alias is in the way"),
                "{mode:?} refused, but not as an alias: {e}"
            );
            assert_eq!(
                std::fs::read(&sentinel).unwrap(),
                SENTINEL,
                "{mode:?} wrote through the link"
            );
            assert!(
                std::fs::symlink_metadata(&leaf)
                    .unwrap()
                    .file_type()
                    .is_symlink(),
                "{mode:?} destroyed the link instead of refusing it"
            );
        }

        // A DIRECTORY symlink is the other shape the error-path peek
        // exists for: the real open asks for `FILE_NON_DIRECTORY_FILE`
        // and reports `STATUS_FILE_IS_A_DIRECTORY`, which says nothing
        // about an alias.
        let dlink = out.join("dlink.bin");
        if plant_dir_link(&outside, &dlink, "the directory-alias arm") {
            let e = open_leaf_at(&dir, &dlink, OsStr::new("dlink.bin"), LeafOpen::Truncate)
                .expect_err("a directory symlink at the leaf name must be refused");
            assert!(
                e.to_string().contains("an alias is in the way"),
                "a directory alias was refused as something else: {e}"
            );
            std::fs::remove_file(&dlink).ok();
        }
        std::fs::remove_file(&leaf).ok();
        std::fs::remove_dir_all(&root).ok();
    }
}
