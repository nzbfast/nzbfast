//! Copy-on-write file duplication: one file's blocks serving N
//! duplicates where the volume can do it, a plain copy where it
//! cannot, and a DESTINATION THAT IS BOUND on every arm.
//!
//! Split out of `disk.rs` on 31 Aug 2026 when that file reached its
//! size ceiling; it is one self-contained mechanism with one public
//! entry point, which is the seam TODO 106 asks splits to follow.

use super::relpath::{self, LeafOpen};
use std::fs::File;
use std::io;
use std::path::Path;

/// Copy `src` to `dst`, preferring a filesystem-level CLONE
/// (copy-on-write) so N duplicates of one file cost one file's blocks
/// instead of N. Falls back to a plain byte copy wherever the clone is
/// refused, and returns the bytes the destination now holds either way.
///
/// THE DESTINATION MUST NOT EXIST, and since 31 Aug 2026 that is a
/// MECHANISM rather than a note to the caller. The name is CLAIMED
/// once, up front, by [`relpath::open_out_leaf`] with
/// [`LeafOpen::CreateNew`] - atomic, exclusive and no-follow on both
/// the leaf and its parent - and every arm below then lands its bytes
/// on that claim. So the destination's parent may not be a symlink,
/// the leaf may not be a symlink, and the name must have been free:
/// `EEXIST` where it was taken, and this module's own refusal where an
/// alias is in the way.
///
/// WHY THAT CHANGED (X5-06/08/19 OWED item 4). This function used to
/// hand both paths to the kernel by name, and `std::fs::copy` - the
/// fallback arm, which is EVERY Windows copy and every copy on a
/// volume without reflinks - FOLLOWS a symlink at its destination and
/// silently overwrites a file that is already there. X5-07 met exactly
/// that at one call site and worked around it locally, with
/// `symlink_metadata` after the fact plus a temp-then-rename; the same
/// rule was by then already spelled once, properly, in `relpath`. Two
/// spellings of one rule is how the next one gets written wrong, so
/// the local workaround's job moved in here and the call site keeps
/// only the assertions that are about CONTENT.
///
/// THE SOURCE IS OPENED, NOT STAT'D, and everything below copies from
/// that one descriptor. A source swapped after the open cannot reach
/// the destination, and a source that will not open returns before
/// anything has been created - which is what keeps "a missing source
/// is an error, never a silent empty destination" true by
/// construction rather than by ordering luck.
///
/// BEST EFFORT BY CONSTRUCTION, and none of the three arms is a promise:
/// macOS clones only on APFS, Linux only on a filesystem with reflink
/// support (btrfs, xfs with `reflink=1`, bcachefs - ext4 has none), and
/// Windows gets the plain copy outright, because block cloning there is
/// a ReFS feature no ordinary install has. A refusal is not an error and
/// is never logged: the bytes land either way, and the only difference
/// is what the volume charges for them. That asymmetry is why nothing
/// asserts a clone happened: a silently dead clone arm costs BLOCKS,
/// never BYTES, and the nzbkit unit tests run on ubuntu (ext4, no
/// reflink) and Windows, where a liveness assertion would be red about
/// a working fallback. VERIFIED BY HAND on the dev Mac (APFS), 30 Aug
/// 2026 and again on 31 Aug after the move to `fclonefileat` plus the
/// rename below: a 512 MiB destination moved the volume's free space by
/// 6.9 MB - which is other lanes on a shared box, not this file - and
/// left no staging temp behind. It is a HAND check and stays one,
/// because free space on this box moves under nine parallel sessions
/// and a test reading it would be flaky about a working arm.
/// The LINUX arm cannot be compiled by any job or box on this fleet (the
/// workspace cross-check dies in libsqlite3-sys' build script for want
/// of a C cross-toolchain), so its one portability hazard - `FICLONE`'s
/// request type, `c_ulong` on glibc and `c_int` on musl - was type
/// checked the same day against a libc-only probe crate on BOTH
/// `x86_64-unknown-linux-gnu` and `armv7-unknown-linux-musleabihf`.
/// Passing `libc::FICLONE` unmodified is what makes one spelling fit
/// both; do not "tidy" it into a literal with a cast.
///
/// THE FALLBACK IS A 1 MiB LOOP, and since 31 Aug 2026 that is a
/// MEASURED choice rather than a stated cost. `std::fs::copy` took the
/// kernel's own copy where it had one; an earlier version of this
/// paragraph said that could not be kept at all, on the ground that it
/// takes no descriptor for its destination, and a later one said it
/// could be kept and simply had not been. Both were wrong in the same
/// direction, and the full measurement is in
/// `research/COWCOPY-FALLBACK-KERNEL-COPY-2026-08-31.md`. THE LOOP
/// STAYS. Two findings decide it and neither is a timing number.
///
/// FIRST, macOS HAS NO `copy_file_range`, so on that platform there is
/// no kernel copy to take. `fcopyfile(from: c_int, to: c_int, ..)` does
/// take two descriptors, but it is libcopyfile's OWN userland
/// read/write loop, not a copy that happens inside the kernel - a C
/// probe naming `copy_file_range` fails to LINK against libSystem,
/// libc 0.2.189 defines that function in its Linux and FreeBSD trees
/// and nowhere else, and `fcopyfile`'s CPU lands between a 64 KiB and a
/// 128 KiB loop, which is what a library copying with a
/// filesystem-blocksize buffer looks like. Measured on the two volumes
/// where this arm can actually run (APFS clones, so it cannot):
/// `fcopyfile` is 24% SLOWER than this loop on HFS+ and 29% faster on
/// exFAT, at a dead heat on CPU. There is no macOS spelling that wins
/// on both, and swapping in one that loses on HFS+ is not an
/// improvement.
///
/// SECOND, on Linux this arm is only ever reached on a volume that has
/// ALREADY REFUSED a reflink - `clone_file_into` runs first and returns
/// on success. `copy_file_range` reaches the filesystem through the
/// same `remap_file_range` hook, so a volume that refuses `FICLONE`
/// refuses it too and it degrades to a kernel-internal page-cache copy.
/// Its whole saving over this loop is then the user-space `memcpy` and
/// the syscall count; it saves no I/O, so it can only pay when the file
/// is already cached. Measured on ext4 (kernel 6.8), interleaved arms,
/// min beside median: it leads by 10% on wall in exactly one shape, a
/// 1 GiB file entirely in the page cache, and at 4 GiB - past RAM,
/// which is the shape a media dedupe actually has - THIS LOOP is 9%
/// ahead. Cold source, a wash. The buffer size was swept in the same
/// pass and 1 MiB is at or within noise of the CPU minimum on both
/// platforms, so that is not a lever either.
///
/// THE ONE CASE THAT WOULD CHANGE THE ANSWER is unmeasured and is
/// written up in that file: a Linux output directory on an SMB3 or
/// NFSv4.2 mount, where `copy_file_range` reaches a SERVER-SIDE copy
/// that our clone arm cannot (SMB3's `remap_file_range` needs ReFS
/// duplicate-extents, which an ordinary NAS has not got) and the bytes
/// never cross the wire. That is a step change rather than a
/// percentage, and it is the thing to reach for if a slow fan-out onto
/// a mounted share is ever reported. It is not a reason to take the
/// change today, and it is no reason at all to touch the macOS arm.
///
/// What makes the loop comfortable meanwhile is that this is not the
/// hot arm: the fan-out this function was written for is bounded by
/// `DUPLICATE_FANOUT_CAP`, and on the two volumes where a dedupe post
/// is actually large (APFS, a reflink Linux volume) no bytes are
/// copied at all - so the loop runs on ext4, on NTFS, and on the odd
/// exFAT stick. A partial destination left behind by a failed copy
/// is NOT removed here, exactly as `std::fs::copy` left one: both
/// callers stage into a private temp and remove it on error, and a
/// removal in here would be a second by-name operation on a path this
/// function has already bound. One further difference from
/// `std::fs::copy`, small but real: the fallback's destination is
/// created with this process's own umask rather than inheriting the
/// source's mode. The clone arms still carry the source's mode, and no
/// caller here reads either.
pub fn copy_file_cow(src: &Path, dst: &Path) -> io::Result<u64> {
    let mut sf = File::open(src)?;

    // The destination, CLAIMED before any arm below runs: the parent
    // may not be an alias, the leaf may not be one, and the name must
    // have been free. Every arm then lands its bytes on this claim
    // rather than on a name it resolves for itself.
    let mut df = relpath::open_out_leaf(dst, LeafOpen::CreateNew)?;

    // A clone writes no bytes, so its count is an `fstat` of the OPEN
    // source - and that is the whole reason the source is opened rather
    // than stat'd by name. A source unlinked mid-settle still answers
    // its own descriptor, where asking the path again would turn a
    // SUCCEEDED clone into an error with the destination already on
    // disk, which is the one answer no caller can act on. Windows has
    // no clone arm, so nothing there asks.
    #[cfg(target_os = "macos")]
    if clone_over_claim(&sf, dst)? {
        return Ok(sf.metadata()?.len());
    }

    // Linux's reflink takes two descriptors, so the claim above IS its
    // destination and a refusal leaves an empty file that the copy
    // below simply fills - where this used to create, refuse, unlink
    // and create again.
    #[cfg(target_os = "linux")]
    if clone_file_into(&sf, &df) {
        return Ok(sf.metadata()?.len());
    }

    stream_copy(&mut sf, &mut df)
}

/// APFS clone onto a destination this function has ALREADY claimed:
/// `fclonefileat` into a private temp beside it, then `renameat` over
/// the claim. False on any refusal (a non-APFS volume, a cross-device
/// pair), which [`copy_file_cow`] answers by copying into the claim it
/// still holds.
///
/// WHY THE TEMP AND THE RENAME, because the obvious spelling was tried
/// first and MEASURED WRONG on 31 Aug 2026. `fclonefileat` names its
/// destination and RESOLVES that name: pointed straight at `dst` with a
/// dangling symlink sitting there, it followed the link and created the
/// file it pointed at, outside the output directory - which is X5-07's
/// defect exactly, reproduced by the syscall this row moved to. There
/// is no `CLONE_NOFOLLOW` for the destination (that flag is about the
/// SOURCE), and no fd-taking clone on this platform at all, so macOS
/// cannot have an atomically-bound clone-create the way Linux's
/// two-descriptor `FICLONE` can.
///
/// What it can have is this: the caller's name is claimed by
/// [`relpath::open_out_leaf`] with `CreateNew`, which IS atomic and IS
/// no-follow, so nothing can be aliased at the name an adversary knows;
/// the only name the clone resolves for itself is a temp built from
/// this process's pid and a nanosecond clock, inside a directory held
/// by DESCRIPTOR; and the publish is `renameat` on that descriptor,
/// which follows nothing and replaces our own claim atomically. The
/// residual is a symlink planted at the temp name in the window before
/// the clone - stated rather than papered over, and not reachable by
/// the adversary this family is about (a hostile NZB or PAR2 chooses
/// DESCRIPTOR names, and cannot choose ours).
#[cfg(target_os = "macos")]
fn clone_over_claim(src: &File, dst: &Path) -> io::Result<bool> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::io::AsRawFd as _;
    let (Some(parent), Some(leaf)) = (dst.parent(), dst.file_name()) else {
        // The claim already succeeded, so this cannot happen - and if a
        // future caller makes it happen, the plain copy is correct.
        return Ok(false);
    };
    // A bare relative name has an EMPTY parent, not none - the current
    // directory, spelled the same way `open_out_leaf` spells it.
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let (Ok(name), Ok(tmp)) = (
        CString::new(leaf.as_bytes()),
        CString::new(temp_leaf().into_bytes()),
    ) else {
        return Ok(false);
    };
    let dir = relpath::open_dir_nofollow(parent)?;
    let dfd = dir.as_raw_fd();
    // SAFETY: `src` and `dir` are borrowed across the call so both
    // descriptors stay live, `tmp` owns the NUL-terminated name, and
    // fclonefileat writes nothing back through any pointer.
    if unsafe { libc::fclonefileat(src.as_raw_fd(), dfd, tmp.as_ptr(), 0) } != 0 {
        return Ok(false);
    }
    // SAFETY: both names are NUL-terminated and owned across the call,
    // `dfd` is live, and renameat writes nothing back.
    if unsafe { libc::renameat(dfd, tmp.as_ptr(), dfd, name.as_ptr()) } != 0 {
        let e = io::Error::last_os_error();
        // SAFETY: same descriptor and name, and unlinkat writes nothing
        // back. Best effort - the clone is already on disk and leaving
        // it there would be the worse answer.
        unsafe { libc::unlinkat(dfd, tmp.as_ptr(), 0) };
        return Err(e);
    }
    Ok(true)
}

/// A staging name inside the destination's own directory that nothing
/// outside this process can predict - this process's pid and the clock,
/// the same construction and the same reasoning as the dedupe pass's
/// own temps, spelled here so the callers do not each have to.
#[cfg(target_os = "macos")]
fn temp_leaf() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    format!(".nzbfast-cow-{}-{nanos:09}.tmp", std::process::id())
}

/// Linux `FICLONE`: a whole-file reflink from `src` into the already
/// created, already bound `dst`. False on any refusal, which
/// [`copy_file_cow`] answers by copying into that same descriptor - so
/// unlike the path-to-path form this replaced, a refusal leaves nothing
/// to unlink and no second create for anything to race.
#[cfg(target_os = "linux")]
fn clone_file_into(src: &File, dst: &File) -> bool {
    use std::os::unix::io::AsRawFd as _;
    // SAFETY: ioctl is handed two open raw fds plus the request code and
    // nothing else; `src` and `dst` are borrowed across the call, and
    // FICLONE writes nothing back through a pointer.
    unsafe { libc::ioctl(dst.as_raw_fd(), libc::FICLONE, src.as_raw_fd()) == 0 }
}

/// The plain-copy arm: `src` into `dst`, both already open, in 1 MiB
/// chunks. Returns the bytes written, which is what
/// [`copy_file_cow`]'s clone arms report from the source's length.
///
/// Both handles are at offset 0 when [`copy_file_cow`] calls this:
/// `dst` has only just been created, and nothing above reads `src` or
/// moves its offset (a refused clone does neither). Neither is seeked
/// here, so a future caller that hands this a used descriptor gets what
/// it asked for rather than a silent rewind.
fn stream_copy(src: &mut File, dst: &mut File) -> io::Result<u64> {
    use std::io::{Read as _, Write as _};
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let n = match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        dst.write_all(&buf[..n])?;
        total += n as u64;
    }
    Ok(total)
}
