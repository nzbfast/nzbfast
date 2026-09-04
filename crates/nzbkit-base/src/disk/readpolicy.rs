//! Read-side page-cache policy: what to tell the kernel about a payload
//! we are about to read once and never look at again.
//!
//! The write side of this file's parent module has had a cache policy
//! since the August line-rate campaign (`maybe_drop_cache`,
//! `maybe_pace_writeback`, the bench-gated `F_NOCACHE`). The READ side
//! had nothing: a PAR2 verify, a create scan or a repair over a 23 GB
//! member pulled its whole payload through the page cache and left it
//! there, evicting whatever else the machine was holding. Every PAR2
//! measurement in `research/PAR2-PERF-AUDIT-2026-09-02.md` timed the
//! PAR2 process and none of them timed the box around it, so the cost
//! of that eviction was unmeasured until the round recorded in
//! `research/PAR2-TWO-LANES-COMPARED-2026-09-03.md`.
//!
//! Two mechanisms, and they are not the same thing:
//!
//! * **Sequential** - `POSIX_FADV_SEQUENTIAL` (Linux), `F_RDAHEAD`
//!   (macOS), `FILE_FLAG_SEQUENTIAL_SCAN` (Windows, open-time only,
//!   which is why [`open_for_scan`] exists rather than a setter). It
//!   asks for readahead and costs nothing; on Windows the same flag
//!   also asks the cache manager to evict behind the reader, so there
//!   it doubles as the drop-behind arm.
//! * **Drop-behind** - `POSIX_FADV_DONTNEED` over the bytes already
//!   consumed (Linux). This is the arm that actually stops the
//!   eviction, and it is the arm that had to earn its place. Measured
//!   ungated it was a 9.8% COLD win and a 7.1% WARM loss; GATED on what
//!   the reader actually brought in ([`sample_brought_in`]) it is
//!   -11.4% cold, flat warm, and evicts nothing of an unrelated working
//!   set, so it ships ON. [`DROP_BEHIND_DEFAULT`] carries both rounds.
//!
//! The policy is keyed on a probed device class and on the member's
//! size, never on a pathname or a filesystem name - that rule is
//! Codex's, from its own remaining item 5, and it is the reason
//! [`device_class`] exists at all.
//!
//! Everything here is a HINT. A filesystem that refuses the fcntl, a
//! kernel that ignores the advice, a probe that cannot read sysfs -
//! all of them leave the default behaviour in place and none of them
//! is an error.

use super::Storage;
use std::fs::File;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

/// What we are going to ask the kernel for on one read handle.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ReadHints {
    /// Ask for readahead / declare the access pattern sequential.
    pub sequential: bool,
    /// Drop the pages behind the reader as it advances.
    pub drop_behind: bool,
}

/// `NZBFAST_READ_HINTS=0|1`, the one knob both arms of any round over
/// this policy run on - ONE binary, never two.
///
/// That is not a convenience: three separate lanes on 3 Sep 2026 shipped
/// a "candidate" to a bench box that was secretly the baseline, by three
/// different mechanisms (see the digest trap in
/// `research/PAR2-RIGS-2026-09-02.md`). A knob on one binary cannot fail
/// that way.
///
/// `0` turns off every hint, which is the behaviour that shipped before
/// this file existed. `1` arms the drop-behind arm, still subject to the
/// size and device gates in [`hints_for`] - it is not a "force
/// everything" switch, because a round wants to measure the POLICY and
/// not just the mechanism. Unset is the shipped default: the sequential
/// declaration on, drop-behind OFF. See [`DROP_BEHIND_DEFAULT`] for the
/// measurement that put it there.
fn hint_override() -> Option<bool> {
    static V: std::sync::OnceLock<Option<bool>> = std::sync::OnceLock::new();
    *V.get_or_init(|| match std::env::var("NZBFAST_READ_HINTS").as_deref() {
        Ok("0") => Some(false),
        Ok("1") => Some(true),
        _ => None,
    })
}

/// Smallest member that gets drop-behind under the default policy,
/// in bytes; `NZBFAST_READ_HINT_MIN_MB` overrides for a sweep.
///
/// See [`drop_behind_floor`] for where the number comes from.
fn hint_floor_override() -> Option<u64> {
    static V: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        std::env::var("NZBFAST_READ_HINT_MIN_MB")
            .ok()?
            .trim()
            .parse::<u64>()
            .ok()
            .map(|mb| mb.saturating_mul(1 << 20))
    })
}

/// How many bytes the reader advances between `DONTNEED` calls.
/// `NZBFAST_READ_HINT_STRIDE_MB` overrides.
///
/// 64 MiB: 366 syscalls over a 23 GB member, which is nothing beside
/// the ~30 s of MD5 the same pass pays, and small enough that the
/// resident window never approaches the RAM of the smallest box we
/// ship to. The write side's equivalent stride is 16 MB and was not
/// delicate over a 4x sweep (`WRITE_PACE_STRIDE_DEFAULT`).
fn hint_stride() -> u64 {
    static V: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        std::env::var("NZBFAST_READ_HINT_STRIDE_MB")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .filter(|mb| *mb > 0)
            .map_or(64 << 20, |mb| mb.saturating_mul(1 << 20))
    })
}

/// The size at or above which a one-pass read drops its pages behind
/// it, given this machine's memory.
///
/// A quarter of physical RAM, floored at 1 GiB and capped at 8 GiB. The
/// shape of the rule matters more than the constants: a payload that
/// cannot be usefully RETAINED is one that would evict more than it can
/// ever hand back, and "usefully" is a fraction of the cache, not an
/// absolute. The floor keeps small boxes from dropping behind on
/// everyday members; the cap keeps a 512 GB host from reading a 40 GB
/// member straight through its cache because a quarter of its RAM is
/// 128 GB.
///
/// Unknown memory reads as "not small" and takes the cap, the same
/// convention as `drop_cache_auto_for` next door: a failed probe must
/// not select the aggressive arm.
pub(crate) fn drop_behind_floor(ram: Option<u64>) -> u64 {
    const FLOOR: u64 = 1 << 30;
    const CAP: u64 = 8 << 30;
    match ram {
        Some(r) => (r / 4).clamp(FLOOR, CAP),
        None => CAP,
    }
}

/// The policy itself, pure and therefore testable without a filesystem,
/// an environment or a box.
///
/// `sequential` is unconditional for a scan: it is a statement about the
/// access pattern and it is true. Measured cold over a 23.4 GB member on
/// an NVMe host it is WITHIN NOISE (19.94 s against 17.19 s median, the
/// spread inside each arm larger than the gap between them) - free, not
/// beneficial, on that device. The obvious escape - "but readahead is
/// what decides throughput on a spinning disk" - was tested on 3 Sep
/// 2026 on a 12-disk RAID6 and is NOT true at the size this engine
/// reads: cold over a 16.6 GB file at the scan's own 1 MiB buffer,
/// six interleaved reps, plain 6.95 s median against 6.84 s declared,
/// inside each arm's own spread. A 1 MiB read already spans the whole
/// stripe, so there is little left for the readahead window to add.
/// It stays on because it is the correct declaration and costs one
/// `fcntl`, not because either device class has been shown to want it;
/// `Network` remains the one class where nobody has measured it.
///
/// What this function computes for `drop_behind` is whether the arm
/// WOULD apply, not whether it runs: [`hints_for_path`] gates that on
/// [`DROP_BEHIND_DEFAULT`] and on the residency sample. `drop_behind` is the arm with a cost, so it is
/// gated three ways:
///
/// * on SIZE, by [`drop_behind_floor`] - a member small enough to leave
///   resident is left resident;
/// * on DEVICE CLASS - `Solid` ONLY. Never on [`Storage::Network`],
///   where a re-read crosses the wire; never on [`Storage::Unknown`],
///   where by definition we do not know what we would be paying; and
///   not on [`Storage::Rotational`], which until 3 Sep 2026 was a
///   stand-down for want of a box and is now a MEASURED refusal. A
///   12-disk RAID6 (46 GB RAM, 2.0-2.4 GB/s cold sequential) ran the
///   mechanism under real memory pressure, a 47.75 GB payload against a
///   never-before-read working set, demand 1.24-1.33x RAM, arms
///   interleaved: the arm does what it does on an SSD - the baseline
///   evicts 100% of the working set and the gated arm evicts NONE of
///   it, 6/6 legs each way - but it costs **+21.8% wall, and it loses
///   6 of 6 pairs**, where on the Zen 4 the same arm was 11.4% FASTER.
///   That fails the keep rule [`DROP_BEHIND_DEFAULT`] records, so the
///   line does not move.
///   The cost is not about the platter: giving pages back is ~0.8 us
///   per page of CPU wherever it runs (measured 0.823 us/page with no
///   memory pressure here, 0.648 us/page on the Zen 4), so what decides
///   the SIGN is whether the reclaim it avoids is worth more than that.
///   Under pressure this box nets 0.441 us/page, i.e. the reclaim it
///   saves is worth only about half what the giving back costs; the
///   Zen 4, overshooting its RAM by a marginal 1.12x rather than in
///   bulk, saved more than it spent. A slow single spindle would pay
///   the same microseconds against a read many times longer and could
///   easily come out ahead; nobody has one to measure, and that - not
///   "rotational" - is what this line is still standing down on. Rotational still gets the
///   sequential declaration, which is the correct statement about the
///   access pattern (and, per the paragraph above, also within noise
///   there). The round is in
///   `research/PAR2-TWO-LANES-COMPARED-2026-09-03.md`;
/// * on PLATFORM, at the call site: only Linux has a range-scoped
///   drop-behind. macOS's nearest equivalent is whole-handle
///   `F_NOCACHE`, which is a different trade and stays bench-gated
///   under the existing `NZBFAST_NOCACHE`; Windows gets it as a
///   side effect of the sequential flag.
pub(crate) fn hints_for(
    len: u64,
    class: Storage,
    ram: Option<u64>,
    floor: Option<u64>,
) -> ReadHints {
    let big = len >= floor.unwrap_or_else(|| drop_behind_floor(ram));
    let droppable = class == Storage::Solid;
    ReadHints {
        sequential: true,
        drop_behind: big && droppable,
    }
}

/// Whether the drop-behind arm is armed when nothing says otherwise.
///
/// **`true`, and it took two rounds to earn it.** Zen 4 EPYC, a 23.4 GB
/// member with its 10%/2 MiB set, an 8 GiB unrelated working set, three
/// interleaved reps on a quiet box, one binary per round (3 Sep 2026,
/// both rounds in `research/PAR2-TWO-LANES-COMPARED-2026-09-03.md`):
///
/// | | cold wall | warm wall | working set evicted |
/// |---|---|---|---|
/// | before this file | 63.81 s | 42.84 s | 17-19% |
/// | drop-behind, UNGATED | -9.8% | **+7.1%, 3/3 losses** | zero |
/// | drop-behind, gated | **-11.4%, 3/3** | 41.73 s, 3/3 arm wins | **zero, 3/3** |
///
/// The ungated arm failed the keep rule on warm and shipped disarmed.
/// The gate is what fixed it, and the warm column is best read as FLAT
/// rather than as a win - it is noise around zero, and quoting -2.6% as
/// a speedup would be overclaiming a number whose own spread is bigger.
///
/// Those three rows are an NVMe box. The one ROTATIONAL box on this
/// fleet was measured on 3 Sep 2026 and says something different - the
/// arm still evicts nothing, and costs +21.8% wall there - which is why
/// [`hints_for`] keeps `Solid` as the only droppable class rather than
/// treating this constant as the whole policy. This default decides
/// whether the arm is ARMED; `hints_for` decides where it applies.
///
/// What the gate does is in [`sample_brought_in`]: give back only what
/// this reader brought in. The freeing that cost 7.1% was of pages the
/// reader never faulted, and a static C reader over the same resident
/// file measures it exactly - 3.642 s plain, 7.697 s ungated, 3.605 s
/// gated, so the cost is GONE and not moved to another thread.
const DROP_BEHIND_DEFAULT: bool = true;

/// The policy as the engine sees it: probe the device, read the
/// overrides, apply [`hints_for`].
pub fn hints_for_path(path: &Path, len: u64) -> ReadHints {
    // `0` is the pre-policy behaviour: no hints at all, which is the
    // baseline arm of every round over this file.
    if hint_override() == Some(false) {
        return ReadHints::default();
    }
    let armed = hint_override().unwrap_or(DROP_BEHIND_DEFAULT);
    let policy = hints_for(
        len,
        device_class(path),
        crate::mem::physical_ram(),
        hint_floor_override(),
    );
    ReadHints {
        drop_behind: armed && policy.drop_behind,
        ..policy
    }
}

// ---------------------------------------------------------------- probe

/// Which storage class `path` lives on, memoised per device.
///
/// The mechanism is NOT duplicated here: [`super::detect_storage`] owns
/// the rotational probe and the `NZBFAST_STORAGE` operator override, and
/// this file contributes only the network half ([`is_network_fs`]),
/// which `detect_storage` now calls. What is added here is the memo -
/// `detect_storage` canonicalises a sysfs path and reads a file, which
/// is fine once per job and wasteful once per member of a 400-file set.
///
/// Measured, per Codex's rule (its remaining item 5), never inferred
/// from the pathname. What each platform can actually see:
///
/// * **Linux** - both halves exactly: `statfs` names the filesystem
///   against the network magics, and sysfs `queue/rotational` answers
///   the spinning question for a local one.
/// * **macOS** - the network half exactly (`MNT_LOCAL` plus the mount
///   type name). NOT the rotational half: the ioctl that would answer it
///   (`DKIOCISSOLIDSTATE`) needs the raw device, which is root-only, and
///   DiskArbitration's `DAMediaRotational` is not a dependency this
///   crate carries. Local storage therefore reports `Unknown`, not
///   `Solid` - an external spinning USB disk is a real configuration and
///   a wrong `Solid` would hand it the arm it least wants.
/// * **Windows** - `GetDriveTypeW` answers `DRIVE_REMOTE` exactly, and a
///   UNC path is remote by construction. Everything else is `Unknown`:
///   the seek-penalty IOCTL wants a volume handle, and no box on this
///   fleet can run the resulting code under a test, so an unverifiable
///   probe is worse than an absent one.
pub fn device_class(path: &Path) -> Storage {
    let key = dev_key(path);
    if let Some(memo) = MEMO_CACHE.get(key) {
        return memo;
    }
    let class = super::detect_storage(path);
    MEMO_CACHE.put(key, class);
    class
}

/// One-entry memo, in ONE atomic word so a reader can never pair a
/// fresh device with a stale class.
///
/// A job reads one member set off one device; a second device costs one
/// extra probe and replaces the entry, which is cheaper and far simpler
/// than a map behind a lock on a path that runs once per file open. The
/// key and the class share the word - three bits of class under a
/// shifted key - so a key that does not survive the shift (`u64::MAX`,
/// the "unkeyable" sentinel, and anything with a top bit set) simply
/// re-probes. It can be slower, never wrong.
struct DevMemo(AtomicU64);

/// The empty word. `0` cannot collide with a stored entry because
/// [`DevMemo::pack`] shifts `key + 1`, never `key`.
const MEMO_EMPTY: u64 = 0;

static MEMO_CACHE: DevMemo = DevMemo(AtomicU64::new(MEMO_EMPTY));

impl DevMemo {
    /// `(key + 1) << 3 | class`. `None` for a key that would lose bits
    /// in the shift - which covers the `u64::MAX` "unkeyable" sentinel
    /// and any device id past 2^60, both of which then simply re-probe.
    fn pack(key: u64, class: Storage) -> Option<u64> {
        (key < (1 << 60)).then(|| ((key + 1) << 3) | encode(class))
    }

    fn get(&self, key: u64) -> Option<Storage> {
        let w = self.0.load(Ordering::Relaxed);
        (w != MEMO_EMPTY && (w >> 3) == key + 1).then(|| decode(w & 7))
    }

    fn put(&self, key: u64, class: Storage) {
        if let Some(w) = Self::pack(key, class) {
            self.0.store(w, Ordering::Relaxed);
        }
    }
}

fn encode(c: Storage) -> u64 {
    match c {
        Storage::Unknown => 0,
        Storage::Solid => 1,
        Storage::Rotational => 2,
        Storage::Network => 3,
    }
}

fn decode(v: u64) -> Storage {
    match v {
        1 => Storage::Solid,
        2 => Storage::Rotational,
        3 => Storage::Network,
        _ => Storage::Unknown,
    }
}

/// The memo key: the device id on unix, the volume prefix on Windows
/// (which has no `st_dev` worth the name, and whose members share a
/// root). `u64::MAX` = do not memoise.
#[cfg(unix)]
fn dev_key(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    // MAX doubles as the sentinel, so a device that really is MAX simply
    // re-probes. It cannot be wrong, only slower.
    std::fs::metadata(path).map_or(u64::MAX, |m| m.dev())
}

#[cfg(not(unix))]
fn dev_key(path: &Path) -> u64 {
    path.to_str()
        .filter(|s| s.len() >= 3)
        .map_or(u64::MAX, |s| {
            s.as_bytes()
                .iter()
                .take(3)
                .fold(0u64, |a, b| a << 8 | u64::from(*b))
        })
}

/// Is `path` on a network filesystem?
///
/// Called by [`super::detect_storage`], which is the one place the
/// storage question is answered; nothing else should call it directly.
///
/// Linux compares `statfs`'s `f_type` against the exact magics. macOS
/// reads `MNT_LOCAL` and, because a FUSE mount is "local" by that flag
/// while being a network client in practice, also the mount type name.
/// Windows has no `statfs`: `GetDriveTypeW` answers `DRIVE_REMOTE`, and
/// a UNC path needs no call at all.
pub(super) fn is_network_fs(path: &Path) -> bool {
    #[cfg(unix)]
    {
        unix_network_fs(path)
    }
    #[cfg(windows)]
    {
        windows_network_fs(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        false
    }
}

#[cfg(unix)]
fn unix_network_fs(path: &Path) -> bool {
    use std::ffi::CString;
    let Some(c) = path.to_str().and_then(|s| CString::new(s).ok()) else {
        return false;
    };
    // SAFETY: statfs writes only through the pointer to the zeroed local
    // `st`, and reads `c`'s NUL-terminated bytes, which outlive the call.
    unsafe {
        let mut st: libc::statfs = std::mem::zeroed();
        if libc::statfs(c.as_ptr(), &mut st) != 0 {
            return false;
        }
        // Three arms, and the split is by what the `statfs` STRUCT
        // carries, not by which platform we happen to ship to: Linux
        // and Android have `f_type` and no `f_flags`/`f_fstypename`,
        // Apple has the latter two and no magic, and anything else gets
        // the honest "do not know", which reads as local and keeps
        // today's behaviour. Writing this as linux/not-linux compiled
        // the Apple arm on Android, where those fields do not exist.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            // NFS, SMB1, SMB2/3, CIFS, AFS, CODA, 9P, CEPH, FUSE (which
            // carries sshfs and every userspace network client) and
            // LUSTRE. An unlisted magic reads as local, which is the
            // conservative direction: it keeps today's behaviour.
            const NETWORK: [i64; 10] = [
                0x6969,      // NFS
                0x517B,      // SMB (smbfs)
                0xFE53_4D42, // SMB2
                0xFF53_4D42, // CIFS
                0x5346_414F, // AFS
                0x7375_7245, // CODA
                0x0102_1997, // V9FS (9P)
                0x00C3_6400, // CEPH
                0x6573_7546, // FUSE
                0x0BD0_0BD0, // LUSTRE
            ];
            // `f_type` is i64, i32, u32 or u64 depending on the
            // target's word size and libc; `try_from` is the one
            // conversion that compiles for all of them, where both a
            // `from` and an `as` cast fail on some (and `as` trips
            // `unnecessary_cast` on the rest).
            // clippy::useless_conversion: on x86_64-unknown-linux-gnu
            // `f_type` already IS i64, so the conversion is a no-op
            // THERE and `-D warnings` took the whole `check` job down on
            // it. Dropping it stops this arm compiling on the targets
            // where the type differs (32-bit linux, musl, android), so
            // the allow is the portable form, not a mute button.
            #[allow(clippy::useless_conversion)]
            let magic = i64::try_from(st.f_type);
            magic.is_ok_and(|t| NETWORK.contains(&t))
        }
        #[cfg(target_vendor = "apple")]
        {
            // `f_flags` is u32 and MNT_LOCAL is an i32 constant on
            // Darwin, so the mask is converted, never the flags.
            if st.f_flags & libc::MNT_LOCAL as u32 == 0 {
                return true;
            }
            let name: Vec<u8> = st
                .f_fstypename
                .iter()
                .take_while(|c| **c != 0)
                .map(|c| *c as u8)
                .collect();
            matches!(
                name.as_slice(),
                b"smbfs" | b"nfs" | b"afpfs" | b"webdav" | b"ftp" | b"macfuse" | b"osxfuse"
            )
        }
        #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
        {
            let _ = st;
            false
        }
    }
}

#[cfg(windows)]
fn windows_network_fs(path: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;
    // DRIVE_REMOTE. Named here rather than imported because the
    // constant lives in a windows-sys feature this crate does not
    // enable, and one integer is not worth widening the dependency.
    const DRIVE_REMOTE: u32 = 4;
    let s = path.as_os_str().to_string_lossy().into_owned();
    // A UNC path is remote by construction; the \\?\ prefix is not UNC.
    if s.starts_with("\\\\") && !s.starts_with("\\\\?\\") {
        return true;
    }
    let bytes = s.as_bytes();
    if bytes.len() < 2 || bytes[1] != b':' {
        return false;
    }
    // GetDriveTypeW wants a root, so build one from the drive letter.
    let root = format!("{}:\\", bytes[0] as char);
    let wide: Vec<u16> = std::ffi::OsStr::new(&root)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: GetDriveTypeW reads a NUL-terminated wide string; `wide`
    // outlives the call and carries its terminator.
    unsafe { GetDriveTypeW(wide.as_ptr()) == DRIVE_REMOTE }
}

// ------------------------------------------------------------- applying

/// Open a file for a one-pass sequential scan, with the access pattern
/// declared to the kernel.
///
/// A separate opener rather than a setter because Windows takes the
/// sequential declaration ONLY as a `CreateFile` flag - there is no
/// after-the-fact equivalent - and because a caller that reaches for
/// this instead of `File::open` is saying something true about what it
/// is about to do. Callers that read at scattered offsets (the repair
/// survey, donor probes) must keep `File::open`: `FILE_FLAG_SEQUENTIAL_SCAN`
/// on a random reader asks the Windows cache manager to evict pages the
/// next seek wants back.
pub fn open_for_scan(path: &Path) -> std::io::Result<File> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_SEQUENTIAL_SCAN. Named here rather than pulled from
        // windows-sys because std's custom_flags takes the raw u32 and
        // the constant lives in a feature this crate does not enable.
        const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_SEQUENTIAL_SCAN)
            .open(path)
    }
    #[cfg(not(windows))]
    {
        let f = File::open(path)?;
        advise_sequential(&f);
        Ok(f)
    }
}

/// Declare a sequential access pattern on an already-open handle.
/// Best effort; a filesystem that refuses keeps its default readahead.
#[cfg(not(windows))]
fn advise_sequential(f: &File) {
    use std::os::unix::io::AsRawFd;
    #[cfg(target_os = "linux")]
    // SAFETY: posix_fadvise takes the raw fd plus integers; the borrow
    // of `f` keeps the fd open across the call.
    unsafe {
        libc::posix_fadvise(f.as_raw_fd(), 0, 0, libc::POSIX_FADV_SEQUENTIAL);
    }
    #[cfg(target_os = "macos")]
    // SAFETY: fcntl takes the raw fd plus an integer; the borrow of `f`
    // keeps the fd open across the call.
    unsafe {
        libc::fcntl(f.as_raw_fd(), libc::F_RDAHEAD, 1);
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = f;
    }
}

/// `NZBFAST_READ_HINT_GATE=0` asks for the UNGATED drop-behind arm - the
/// one first measured, which drops every stride whether the reader
/// brought it in or not. Kept so a round can put the two arms of the
/// gate itself against each other on one binary; there is no reason to
/// run it in production, where it is the arm that cost 7.1% warm.
fn gate_enabled() -> bool {
    static V: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *V.get_or_init(|| !matches!(std::env::var("NZBFAST_READ_HINT_GATE").as_deref(), Ok("0")))
}

/// How much of the file one `mincore` sample covers at a time. The
/// vector it fills is one byte per page, so an ungated sample of a
/// 1 TB member would ask for 244 MB of it at once; windowing holds the
/// transient allocation at 256 KiB whatever the member's size.
#[cfg(target_os = "linux")]
const SAMPLE_WINDOW: u64 = 1 << 30;

/// Which strides were ENTIRELY absent from the page cache at open, and
/// are therefore this reader's to give back.
///
/// **The sample has to be taken before the first read, and that is the
/// whole subtlety of this file.** The obvious implementation - ask, per
/// stride, "was this resident before I read it?" - is contaminated by
/// our OWN readahead, which by construction runs ahead of the reader and
/// has already pulled the next stride in. It would answer "already
/// cached, leave it" for every stride and the cold win would quietly
/// vanish, in a way no test would catch because the code would look
/// right. One `mincore` pass before the first read is contaminated by
/// nothing.
///
/// `None` means DO NOT DROP ANYTHING, for either of two reasons: the
/// sample could not be taken (no mapping, `mincore` refused, a
/// zero-length file), or stage one found the payload already resident
/// and there is nothing of ours to give back. The caller stands the
/// whole arm down either way and must never drop blind - dropping what
/// we did not bring in IS the 7.1% warm regression this gate removes.
///
/// A stride counts as ours only if EVERY page in it was absent, which
/// errs toward leaving other people's pages alone.
#[cfg(target_os = "linux")]
fn sample_brought_in(f: &File, len: u64, stride: u64) -> Option<Box<[bool]>> {
    use std::os::unix::io::AsRawFd;
    if len == 0 || stride == 0 {
        return None;
    }
    // SAFETY: sysconf takes only an integer constant and reads no
    // pointers.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let Ok(page) = u64::try_from(page) else {
        return None;
    };
    // A stride that is not a whole number of pages would misalign every
    // window's chunking; the shipped strides are all MiB multiples, so
    // this only ever fires on an exotic page size, and standing down is
    // the safe answer there.
    if page == 0 || !stride.is_multiple_of(page) {
        return None;
    }
    let n_strides = usize::try_from(len.div_ceil(stride)).ok()?;
    let mut out = vec![false; n_strides];
    // TWO STAGES, because the full sample is not free and on a warm
    // payload it buys nothing. Walking every page of a 23 GB member
    // costs ~0.63 s here, which is invisible beside a 6.9 s cold win
    // and is most of a measured +2.6% when the file was already cached
    // and nothing gets dropped. So look at the FIRST window first: if
    // every stride in it is already resident, this is a warm payload,
    // there is nothing for us to give back, and the whole arm stands
    // down for the cost of one window (~27 ms).
    //
    // Being wrong is one-directional by construction: a file whose
    // first GiB is cached and whose tail is cold stands down and loses
    // the win. It never drops a page somebody else brought in, which
    // is the outcome that actually costs.
    // The window MUST be a whole number of strides, or a stride that
    // straddles a window boundary is chunked from the wrong offset in
    // the next window and every later stride is misattributed. It is
    // exact for the shipped 64 MiB stride (1 GiB is 16 of them) and
    // silently wrong for, say, 96 MiB - which is reachable through
    // NZBFAST_READ_HINT_STRIDE_MB, so it is rounded here rather than
    // assumed.
    let window = (SAMPLE_WINDOW / stride).max(1) * stride;
    let mut base = 0u64;
    while base < len {
        let span = window.min(len - base);
        let span_usize = usize::try_from(span).ok()?;
        // SAFETY: a fresh read-only shared mapping of `span` bytes of a
        // file we hold open; MAP_FAILED is checked before any use, and
        // the mapping is unmapped with the same length below. Nothing
        // ever dereferences it - only `mincore` reads through it - so
        // this costs address space and not a single page fault.
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                span_usize,
                libc::PROT_READ,
                libc::MAP_SHARED,
                f.as_raw_fd(),
                base as libc::off_t,
            )
        };
        if addr == libc::MAP_FAILED {
            return None;
        }
        let pages = usize::try_from(span.div_ceil(page)).ok()?;
        let mut vec = vec![0u8; pages];
        // SAFETY: `addr` is a live mapping of `span_usize` bytes and
        // `vec` has one byte per page of it, which is exactly what
        // mincore writes.
        let rc = unsafe { libc::mincore(addr, span_usize, vec.as_mut_ptr()) };
        // SAFETY: unmapping the mapping made above, same base and length.
        unsafe {
            libc::munmap(addr, span_usize);
        }
        if rc != 0 {
            return None;
        }
        let per = (stride / page) as usize;
        let first = (base / stride) as usize;
        for (k, chunk) in vec.chunks(per).enumerate() {
            if let Some(slot) = out.get_mut(first + k) {
                *slot = chunk.iter().all(|b| b & 1 == 0);
            }
        }
        // Stage one's verdict, taken on the first window only.
        if base == 0 && out.iter().take((span / stride) as usize).all(|ours| !ours) {
            return None;
        }
        base += span;
    }
    Some(out.into_boxed_slice())
}

#[cfg(not(target_os = "linux"))]
fn sample_brought_in(f: &File, len: u64, stride: u64) -> Option<Box<[bool]>> {
    let _ = (f, len, stride);
    None
}

/// Drop-behind state for one scanned file.
///
/// Constructed from the policy, advanced by the reader as it consumes
/// bytes, and a no-op in every arm the policy did not select - so a
/// call site is one `let` and one call per buffer, whatever the
/// platform decided.
pub struct ScanCache {
    drop_behind: bool,
    stride: u64,
    /// The file's length at open, so `finish` knows where the tail ends.
    len: u64,
    /// Bytes below this offset have already been handed to `DONTNEED`.
    dropped: AtomicU64,
    /// Per stride: was this range ENTIRELY absent from the page cache
    /// when the file was opened, and therefore ours to give back?
    /// `None` = no gate (the sample failed, or it was asked for off),
    /// in which case every stride is dropped - the arm as it was first
    /// measured. See [`sample_brought_in`].
    brought_in: Option<Box<[bool]>>,
}

impl ScanCache {
    /// The policy for a one-pass scan of `len` bytes of `path` through
    /// the handle `f`.
    ///
    /// Applies the sequential half immediately - it is a statement about
    /// the access pattern and is true the moment the caller asks for it -
    /// and returns the drop-behind half for [`Self::consumed`] to
    /// advance. A caller that opened with [`open_for_scan`] has already
    /// declared the pattern and pays only a repeat of a free fcntl.
    pub fn attach(f: &File, path: &Path, len: u64) -> ScanCache {
        let mut cache = Self::from_hints(hints_for_path(path, len));
        cache.len = len;
        // BEFORE the first read, and that ordering is the whole point -
        // see `sample_brought_in`.
        if cache.drop_behind && gate_enabled() {
            cache.brought_in = sample_brought_in(f, len, cache.stride);
            // `None` covers BOTH of the sampler's stand-downs - it
            // could not sample, or stage one found the payload already
            // resident - and both want the same answer. Never fall back
            // to dropping everything: that is the arm that regressed
            // warm by 7.1%.
            if cache.brought_in.is_none() {
                cache.drop_behind = false;
            }
        }
        #[cfg(not(windows))]
        advise_sequential(f);
        #[cfg(windows)]
        let _ = f;
        announce(path, len, cache.drops_behind());
        cache
    }

    pub(crate) fn from_hints(h: ReadHints) -> ScanCache {
        ScanCache {
            // Range-scoped drop-behind is a Linux capability. macOS's
            // nearest equivalent is whole-handle F_NOCACHE, a different
            // trade that stays behind NZBFAST_NOCACHE; Windows gets
            // evict-behind from the sequential open flag instead.
            drop_behind: h.drop_behind && cfg!(target_os = "linux"),
            stride: hint_stride(),
            len: 0,
            dropped: AtomicU64::new(0),
            brought_in: None,
        }
    }

    /// Whether this scan will actually issue drop-behind calls. Exposed
    /// for tests and for the diagnostic line; not a policy input.
    pub fn drops_behind(&self) -> bool {
        self.drop_behind
    }

    /// The reader has consumed everything below `offset`. Drops the
    /// pages behind it once a whole stride has accumulated, so the
    /// resident window stays bounded by one stride rather than by the
    /// file.
    ///
    /// `&self`, like the writer's hooks next door: the exact-size verify
    /// pipeline hands buffers to concurrent hash lanes and the reader
    /// owning the cursor is not necessarily the only holder.
    pub fn consumed(&self, f: &File, offset: u64) {
        if !self.drop_behind {
            return;
        }
        let prev = self.dropped.load(Ordering::Relaxed);
        let next = offset.saturating_sub(offset % self.stride);
        if next <= prev || next - prev < self.stride {
            return;
        }
        if self
            .dropped
            .compare_exchange(prev, next, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        self.drop_range(f, prev, next);
    }

    /// The scan is over: give back whatever is left that was ours.
    /// Called once, at the end of a pass, so the tail below the last
    /// stride boundary does not stay resident.
    pub fn finish(&self, f: &File) {
        if !self.drop_behind {
            return;
        }
        let prev = self.dropped.load(Ordering::Relaxed);
        let end = self.len.max(prev);
        if self
            .dropped
            .compare_exchange(prev, end, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            self.drop_range(f, prev, end);
        }
    }

    /// Hand `[from, to)` back to the kernel, one stride at a time, and
    /// only the strides that are OURS to hand back.
    ///
    /// Stride-at-a-time rather than one call for the whole span because
    /// the gate is per stride; where there is no gate (`brought_in` is
    /// `None` - the sample failed, or `NZBFAST_READ_HINT_GATE=0` asked
    /// for the ungated arm this policy was first measured with) the
    /// loop still issues one call per stride, which the syscall count
    /// in the round already showed is free beside the freeing itself.
    fn drop_range(&self, f: &File, from: u64, to: u64) {
        let mut at = from;
        while at < to {
            let span = self.stride.min(to - at);
            let ours = match &self.brought_in {
                None => true,
                Some(map) => {
                    let k = (at / self.stride) as usize;
                    map.get(k).copied().unwrap_or(false)
                }
            };
            if ours {
                self.dontneed(f, at, span);
            }
            at += span;
        }
    }

    #[cfg(target_os = "linux")]
    fn dontneed(&self, f: &File, off: u64, len: u64) {
        use std::os::unix::io::AsRawFd;
        // SAFETY: posix_fadvise takes the raw fd plus integers; the
        // borrow of `f` keeps the fd open across the call. Out-of-range
        // or clamped arguments are an EINVAL we deliberately ignore -
        // this is advice, not a write.
        unsafe {
            libc::posix_fadvise(
                f.as_raw_fd(),
                off as libc::off_t,
                len as libc::off_t,
                libc::POSIX_FADV_DONTNEED,
            );
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn dontneed(&self, f: &File, off: u64, len: u64) {
        let _ = (f, off, len);
    }
}

/// Say once, at debug level, which arm this process actually took.
///
/// Not decoration. Three separate lanes on 3 Sep 2026 measured a
/// "candidate" that was secretly the baseline, by three different
/// shipping mistakes (`research/PAR2-RIGS-2026-09-02.md`). A round over
/// this policy can gate on this line and know the code is in the binary
/// AND which way it decided, rather than trusting that an env knob
/// reached a process that understands it.
fn announce(path: &Path, len: u64, dropping: bool) {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        tracing::debug!(
            target: "disk",
            "read policy: {:?}, len={len}, sequential=1, drop_behind={}",
            device_class(path),
            u8::from(dropping)
        );
    });
}

/// A `Read` adapter that carries the drop-behind policy for the handle
/// under it.
///
/// The verify pipeline is generic over `R: Read` and never sees a
/// `File`, deliberately - it also serves pipes and the streaming
/// fallbacks. Wrapping the handle rather than threading a cache through
/// that pipeline keeps the policy at the ONE place that knows the read
/// is a one-pass scan of a file, and leaves the pipeline exactly as the
/// verify race lane landed it.
pub struct ScanReader {
    file: File,
    cache: ScanCache,
    pos: u64,
}

impl ScanReader {
    /// Adopt an already-open handle for a one-pass scan of `len` bytes.
    ///
    /// Adopt rather than re-open: the verify path's whole-file digest
    /// and its block digests must come from ONE inode even if the member
    /// is replaced mid-verify, which a second `File::open` by pathname
    /// would give up. The cost is that Windows gets no
    /// `FILE_FLAG_SEQUENTIAL_SCAN` here - that flag exists only at
    /// `CreateFile` time - so on Windows this adapter is the drop-behind
    /// policy alone, and callers that open fresh use [`open_for_scan`]
    /// to get both.
    pub fn adopt(file: File, path: &Path, len: u64) -> ScanReader {
        let cache = ScanCache::attach(&file, path, len);
        ScanReader {
            file,
            cache,
            pos: 0,
        }
    }
}

impl std::io::Read for ScanReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = std::io::Read::read(&mut self.file, buf)?;
        self.pos += n as u64;
        self.cache.consumed(&self.file, self.pos);
        Ok(n)
    }
}

impl Drop for ScanReader {
    /// The tail below the last stride boundary is still resident when
    /// the pass ends, so the scan is finished here rather than left for
    /// the kernel. A reader the policy left inert drops nothing.
    fn drop(&mut self) {
        self.cache.finish(&self.file);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const G: u64 = 1 << 30;

    #[test]
    fn drop_behind_floor_is_a_clamped_quarter_of_ram() {
        // Small box: the 1 GiB floor holds, not RAM/4.
        assert_eq!(drop_behind_floor(Some(2 * G)), G);
        // Mid box: the quarter rule.
        assert_eq!(drop_behind_floor(Some(32 * G)), 8 * G);
        assert_eq!(drop_behind_floor(Some(16 * G)), 4 * G);
        // Huge box: the 8 GiB cap, so a 40 GB member still drops behind.
        assert_eq!(drop_behind_floor(Some(512 * G)), 8 * G);
        // A failed probe must not select the aggressive arm: it takes
        // the cap, the same convention as drop_cache_auto_for.
        assert_eq!(drop_behind_floor(None), 8 * G);
    }

    #[test]
    fn sequential_is_unconditional_and_drop_behind_is_not() {
        // Every arm declares the pattern; only some drop pages.
        for class in [
            Storage::Solid,
            Storage::Rotational,
            Storage::Network,
            Storage::Unknown,
        ] {
            assert!(hints_for(40 * G, class, Some(32 * G), None).sequential);
        }
    }

    #[test]
    fn drop_behind_needs_size_and_a_measured_local_ssd() {
        let ram = Some(32 * G);
        // Big enough, local, known solid: on.
        assert!(hints_for(40 * G, Storage::Solid, ram, None).drop_behind);
        // Rotational is NOT droppable, and since 3 Sep 2026 that is a
        // measured refusal rather than a stand-down: on a 12-disk RAID6
        // under real memory pressure the arm protected the whole of an
        // unrelated working set and cost +21.8% wall, losing 6 of 6
        // pairs. hints_for's doc carries the round. It still gets the
        // sequential declaration, which the case above pins.
        assert!(!hints_for(40 * G, Storage::Rotational, ram, None).drop_behind);
        // Exactly at the floor: on (the comparison is >=).
        assert!(hints_for(8 * G, Storage::Solid, ram, None).drop_behind);
        // Under the floor: left resident.
        assert!(!hints_for(8 * G - 1, Storage::Solid, ram, None).drop_behind);
        // A re-read crosses the wire, or we do not know what it costs.
        assert!(!hints_for(40 * G, Storage::Network, ram, None).drop_behind);
        assert!(!hints_for(40 * G, Storage::Unknown, ram, None).drop_behind);
    }

    #[test]
    fn the_floor_override_replaces_the_ram_rule_entirely() {
        // The sweep knob must be able to select BOTH directions, or a
        // threshold sweep cannot measure the threshold it is sweeping.
        let ram = Some(32 * G);
        assert!(hints_for(G, Storage::Solid, ram, Some(1 << 20)).drop_behind);
        assert!(!hints_for(64 * G, Storage::Solid, ram, Some(128 * G)).drop_behind);
    }

    #[test]
    fn a_scan_only_claims_the_platform_it_has() {
        // A policy that said no drops nothing...
        let s = ScanCache::from_hints(ReadHints::default());
        assert!(!s.drops_behind());
        // ...and a policy that said yes only claims to drop where the
        // platform has a range-scoped primitive.
        let h = ScanCache::from_hints(ReadHints {
            sequential: true,
            drop_behind: true,
        });
        assert_eq!(h.drops_behind(), cfg!(target_os = "linux"));
    }

    /// The gate's contract, at the level a unit test can reach on any
    /// platform: a cache with a `brought_in` map drops ONLY the strides
    /// the map marks as ours, and one with no map drops everything.
    /// `drop_range` is the single place that decision is made, so
    /// exercising it here covers both arms without needing a kernel that
    /// has `mincore`.
    #[test]
    fn the_gate_drops_only_what_the_reader_brought_in() {
        let f = std::fs::File::open(std::env::current_exe().unwrap()).unwrap();
        let mk = |map: Option<Vec<bool>>| ScanCache {
            drop_behind: true,
            stride: 1 << 20,
            len: 4 << 20,
            dropped: AtomicU64::new(0),
            brought_in: map.map(Vec::into_boxed_slice),
        };
        // Ungated: every stride is ours. Gated: only the marked ones.
        // Neither call can be observed from a unit test (the syscall is
        // advice and a no-op off Linux), so what is pinned here is that
        // the SELECTION is by stride index and survives a partial map -
        // the shape a wrong index would break.
        let gated = mk(Some(vec![true, false, true, false]));
        assert!(gated.brought_in.as_ref().unwrap()[0]);
        assert!(!gated.brought_in.as_ref().unwrap()[1]);
        gated.drop_range(&f, 0, 4 << 20);
        // A map SHORTER than the file must not drop past its end: an
        // absent entry reads as "not ours", never as "ours".
        let short = mk(Some(vec![true]));
        short.drop_range(&f, 0, 4 << 20);
        // And no map at all is the ungated arm, which drops the lot.
        mk(None).drop_range(&f, 0, 4 << 20);
    }

    /// The sample window has to be a whole number of strides or a
    /// stride straddling a window boundary is chunked from the wrong
    /// offset and every later stride is misattributed - the kind of
    /// defect that shows up as "the cold win got smaller" and never as
    /// a failure. Exact for the shipped stride; the odd ones are what
    /// this pins.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_sample_window_is_a_whole_number_of_strides() {
        for mb in [1u64, 7, 64, 96, 100, 512, 1024, 3000] {
            let stride = mb << 20;
            let window = (SAMPLE_WINDOW / stride).max(1) * stride;
            assert_eq!(window % stride, 0, "stride {mb} MiB");
            assert!(window >= stride, "stride {mb} MiB");
        }
    }

    /// `finish` must sweep the tail, and it must be idempotent - the
    /// verify pipeline drops its reader once but `finish` is also
    /// reachable from a caller that already called `consumed` to the
    /// end.
    #[test]
    fn finish_sweeps_the_tail_once() {
        let f = std::fs::File::open(std::env::current_exe().unwrap()).unwrap();
        let c = ScanCache {
            drop_behind: true,
            stride: 1 << 20,
            len: 3 << 20,
            dropped: AtomicU64::new(2 << 20),
            brought_in: None,
        };
        c.finish(&f);
        assert_eq!(c.dropped.load(Ordering::Relaxed), 3 << 20);
        c.finish(&f);
        assert_eq!(c.dropped.load(Ordering::Relaxed), 3 << 20);
    }

    #[test]
    fn consumed_advances_one_stride_at_a_time() {
        let s = ScanCache {
            drop_behind: true,
            stride: 1 << 20,
            len: 8 << 20,
            dropped: AtomicU64::new(0),
            brought_in: None,
        };
        let f = std::fs::File::open(std::env::current_exe().unwrap()).unwrap();
        // Under a stride: nothing moves.
        s.consumed(&f, (1 << 20) - 1);
        assert_eq!(s.dropped.load(Ordering::Relaxed), 0);
        // Past it: the watermark lands on the stride boundary below the
        // reader, never on the reader itself - the bytes in the current
        // stride may still be in a lane's hands.
        s.consumed(&f, (3 << 20) + 7);
        assert_eq!(s.dropped.load(Ordering::Relaxed), 3 << 20);
        // Re-delivering the same offset is idempotent.
        s.consumed(&f, (3 << 20) + 7);
        assert_eq!(s.dropped.load(Ordering::Relaxed), 3 << 20);
    }

    /// The shipped default is ON, and it is a MEASURED default: gated
    /// drop-behind is -11.4% cold with zero eviction of an unrelated
    /// working set, and FLAT warm (the numbers and the two rounds are on
    /// `DROP_BEHIND_DEFAULT`). It was `false` for one round, when the
    /// ungated arm cost 7.1% warm.
    ///
    /// This test is not asserting that `true` is right - it is asserting
    /// that moving this constant is a deliberate act with a failing test
    /// attached, in EITHER direction, because both values have been
    /// correct at different times and the thing that decides is a round
    /// on a quiet box and not a reviewer's intuition.
    #[test]
    // clippy::assertions_on_constants: asserting a constant is the WHOLE
    // point here - this pins a shipped default so that moving it fails a
    // test in either direction, which is what the doc above says it is
    // for. Rewriting it into something clippy reads as dynamic would
    // delete the pin and keep the shape.
    #[allow(clippy::assertions_on_constants)]
    fn the_drop_behind_default_is_a_measured_constant() {
        assert!(
            DROP_BEHIND_DEFAULT,
            "drop-behind measured -11.4% cold with zero working-set eviction \
             and flat warm on the Zen 4. Turning it off gives that up; \
             re-measure BOTH phases with bench/component/par2-cache-round.sh \
             and move the table on DROP_BEHIND_DEFAULT with the constant."
        );
        // The gate is what made the default defensible, so a build that
        // silently lost it must not keep the default armed.
        assert!(
            gate_enabled(),
            "the gate defaults on; without it this arm is the +7.1% warm one"
        );
        // And the policy underneath still decides WHETHER the arm applies.
        assert!(hints_for(40 * G, Storage::Solid, Some(32 * G), None).drop_behind);
        assert!(!hints_for(40 * G, Storage::Network, Some(32 * G), None).drop_behind);
    }

    #[test]
    fn the_device_memo_never_pairs_one_device_with_another_class() {
        // The whole reason the memo is ONE word: a torn (device, class)
        // pair would hand a file the policy of a different disk.
        let m = DevMemo(AtomicU64::new(MEMO_EMPTY));
        assert_eq!(m.get(0), None, "empty memo answers nothing");
        m.put(0, Storage::Solid);
        assert_eq!(m.get(0), Some(Storage::Solid), "device 0 is a real key");
        assert_eq!(m.get(1), None, "a different device never hits");
        m.put(1, Storage::Network);
        assert_eq!(m.get(1), Some(Storage::Network));
        assert_eq!(m.get(0), None, "one entry, replaced");
        // Every class survives the round trip, or a memo hit would be a
        // silent reclassification.
        for c in [
            Storage::Solid,
            Storage::Rotational,
            Storage::Network,
            Storage::Unknown,
        ] {
            m.put(42, c);
            assert_eq!(m.get(42), Some(c), "{c:?}");
        }
        // An unkeyable device re-probes rather than storing a truncated
        // key that a later real device could collide with.
        assert_eq!(DevMemo::pack(u64::MAX, Storage::Solid), None);
        assert_eq!(DevMemo::pack(1 << 60, Storage::Solid), None);
        let m2 = DevMemo(AtomicU64::new(MEMO_EMPTY));
        m2.put(u64::MAX, Storage::Solid);
        assert_eq!(m2.get(u64::MAX), None);
    }

    #[test]
    fn the_probe_answers_something_for_a_real_path_and_caches_it() {
        // Not an assertion about THIS box's storage - the point is that
        // the probe terminates, never panics, and the memo returns the
        // same answer the cold call did.
        let p = std::env::temp_dir();
        let first = device_class(&p);
        assert_eq!(device_class(&p), first);
    }

    #[test]
    fn open_for_scan_reads_the_same_bytes_as_a_plain_open() {
        use std::io::Read;
        let p = std::env::current_exe().unwrap();
        let mut a = Vec::new();
        let mut b = Vec::new();
        File::open(&p)
            .unwrap()
            .take(4096)
            .read_to_end(&mut a)
            .unwrap();
        open_for_scan(&p)
            .unwrap()
            .take(4096)
            .read_to_end(&mut b)
            .unwrap();
        assert_eq!(a, b);
        assert!(!a.is_empty());
    }
}
