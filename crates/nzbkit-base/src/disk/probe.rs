//! What a path is sitting on, and what that costs: the [`Storage`]
//! classes, the probe that answers for a path, the `NZBFAST_STORAGE`
//! override, the sysfs/mount-table rotational reads behind it, and the
//! one decision the download path makes off the answer
//! (`decoders_for_storage`).
//!
//! Cut out of `disk.rs` on 7 Sep 2026 (claim `debt-split-hot-files-7sep`)
//! at 3,683 of the size gate's 4,000-line file ceiling. Verbatim move;
//! the public items are re-exported beside the `mod` line.

use super::*;

/// What a path is sitting on.
///
/// `Unknown` is a first-class answer and must never be treated as
/// `Rotational`: device mapper, RAID, overlayfs in a container and
/// every non-Linux local disk land here, and guessing "spinning" for
/// them would clamp hardware that has no seek problem.
///
/// `Network` was added 3 Sep 2026 by the read-side cache policy
/// (`readpolicy`), which needs to know what a RE-READ costs and not
/// only what a seek costs - a payload dropped from the page cache on
/// an SMB share is fetched again over the wire. It is a separate
/// variant rather than a second enum because there is one storage
/// question in this tree and it gets one answer; `decoders_for_storage`
/// treats it exactly as it treated the `Unknown` these mounts used to
/// report, so the download path's behaviour is unchanged by the split.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Storage {
    Rotational,
    Solid,
    /// SMB/CIFS, NFS, AFP, WebDAV, 9P or a FUSE client. Local seek cost
    /// unknown; a re-read crosses a wire.
    Network,
    Unknown,
}

/// A storage class and HOW it was reached.
///
/// Two fields because two different questions are asked of this probe
/// and only one of them is answered by the class alone. The read-side
/// cache policy wants to know what a RE-READ costs, which is a property
/// of the device; the decode-worker clamp and the spill governor's
/// stand-down want to know whether OUR WRITE ORDER is the order the
/// platter sees, which is a property of the filesystem on top of it.
/// [`StorageProbe::direct_dev`] is what separates them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StorageProbe {
    /// What the storage is.
    pub class: Storage,
    /// `true` when `class` was read off the block device that the
    /// filesystem's OWN `st_dev` names, or asserted by the operator
    /// through `NZBFAST_STORAGE`.
    ///
    /// `false` means `st_dev` was ANONYMOUS and the device had to be
    /// found through the mount table (`disk::mounttab`). That is not
    /// merely a weaker probe. The filesystems with an anonymous device
    /// are exactly the ones that put a layer between a `pwrite` offset
    /// and a platter address - btrfs and ZFS copy on write, overlayfs
    /// writes into a different filesystem entirely - so a rule that
    /// exists because "N decode workers become N seek lanes" does not
    /// follow there even when the class is right.
    ///
    /// `Unknown` and `Network` carry `true` because there is no indirect
    /// answer for the flag to qualify - including the case where the
    /// fallback ran and stood down, which is what overlayfs inside a
    /// container does (measured: its mountinfo source is the word
    /// `overlay`, and its `upperdir=` names a path in the HOST).
    pub direct_dev: bool,
}

/// What is under `path`, with `NZBFAST_STORAGE=rotational|ssd|auto` as the
/// operator override (`auto`, or anything unset, probes).
///
/// The probe matters because decoded articles `pwrite` at their final
/// offsets: with several decode workers the network's article lanes become
/// the output file's seek lanes, which a spinning disk pays for and an SSD
/// does not.
///
/// The thin reading of [`probe_storage`], for the callers that only want
/// the class. `decoders_for_storage` is the one that wants the rest.
pub fn detect_storage(path: &Path) -> Storage {
    probe_storage(path).class
}

/// [`detect_storage`], plus how the answer was reached.
///
/// ONE probe, one answer, richer answer - the storage question is not
/// duplicated anywhere else in this tree and must not be. The two arms
/// are tried in order: the filesystem's own device id first, and the
/// mount table only when that names nothing.
pub fn probe_storage(path: &Path) -> StorageProbe {
    let direct = |class| StorageProbe {
        class,
        direct_dev: true,
    };
    if let Some(forced) = storage_override(std::env::var("NZBFAST_STORAGE").ok().as_deref()) {
        // The operator asserting a class asserts it for every reader:
        // `NZBFAST_STORAGE=rotational` has clamped decoders since the
        // clamp existed and must keep doing so.
        return direct(forced);
    }
    // Asked BEFORE the rotational flag because a network mount has no
    // block device to read one from: on Linux it would fall through to
    // `Unknown`, and on macOS `rotational` answers `None` for
    // everything. The operator override still wins over both.
    if readpolicy::is_network_fs(path) {
        return direct(Storage::Network);
    }
    if let Some(spinning) = rotational(path) {
        return direct(class_of(spinning));
    }
    match rotational_via_mount_table(path) {
        Some(spinning) => StorageProbe {
            class: class_of(spinning),
            direct_dev: false,
        },
        None => direct(Storage::Unknown),
    }
}

/// The rotational flag as a class. One place, so the two arms of
/// [`probe_storage`] cannot come to disagree about which way round it is.
pub(super) fn class_of(spinning: bool) -> Storage {
    if spinning {
        Storage::Rotational
    } else {
        Storage::Solid
    }
}

/// The `NZBFAST_STORAGE` override, parsed. Split out so the mapping is
/// testable without mutating the environment: tests share one process, so
/// a `set_var` here would race every other test that probes storage.
pub(super) fn storage_override(raw: Option<&str>) -> Option<Storage> {
    match raw {
        Some("rotational") | Some("hdd") => Some(Storage::Rotational),
        Some("ssd") | Some("solid") => Some(Storage::Solid),
        _ => None,
    }
}

/// Read the backing block device's `queue/rotational` flag, using the
/// filesystem's OWN device id and nothing else.
///
/// The device id of the file's filesystem indexes `/sys/dev/block`, which
/// for a partition resolves to the partition's directory - `queue/` lives
/// on the parent disk, hence the walk up one level.
///
/// **A whole family of filesystems has no device id to index with, and
/// this answers `None` for every one of them.** btrfs, ZFS and overlayfs
/// allocate an ANONYMOUS block device (`major 0`), so `st_dev` names
/// nothing under `/sys/dev/block` and the canonicalize below fails.
/// Measured on the fleet's rotational NAS on 3 Sep 2026 with the
/// `readpolicy_probe` example, on the box: its btrfs data volume (twelve
/// spinning disks, every one of them reporting `queue/rotational 1`)
/// answered `class=Unknown`, while `/` on ext4 over the same disks
/// answered `class=Rotational`.
///
/// **That hole is no longer the end of the probe** (TODO 325, 4 Sep
/// 2026): [`probe_storage`] falls through to `mounttab`, which finds the
/// device the mount was made from instead, and the NAS volume above now
/// answers `Rotational`. This function is deliberately left as the
/// narrow question it always was - it is the arm whose answer carries
/// `direct_dev`, i.e. the one a caller may read as a statement about
/// write ORDER and not only about the device. The round that found the
/// hole is in `research/PAR2-TWO-LANES-COMPARED-2026-09-03.md`; the one
/// that closed it, including the three shapes that broke the obvious
/// designs, is `research/STORAGE-PROBE-ANON-DEV-2026-09-04.md`.
#[cfg(target_os = "linux")]
pub(super) fn rotational(path: &Path) -> Option<bool> {
    use std::os::unix::fs::MetadataExt;
    // Probe the directory itself, not a file inside it: the caller may not
    // have created anything yet.
    let dev = std::fs::metadata(path).ok()?.dev();
    // libc::major/minor are safe fns on Linux (they only bit-shift the
    // integer dev value) - an `unsafe` block here trips `-D unused-unsafe`
    // on the CI runner, the one platform that compiles this cfg.
    let (major, minor) = (libc::major(dev), libc::minor(dev));
    sysfs_rotational(format!("/sys/dev/block/{major}:{minor}"))
}

/// `queue/rotational` under a sysfs block-device directory, with the
/// parent walk a partition needs.
///
/// Shared with `mounttab`, which reaches the same file by a different
/// route: one reader for one file, so the two arms of the probe cannot
/// come to disagree about what `1` means or where `queue/` lives.
#[cfg(target_os = "linux")]
pub(super) fn sysfs_rotational(dir: impl AsRef<Path>) -> Option<bool> {
    let sys = std::fs::canonicalize(dir).ok()?;
    let read = |dir: &Path| -> Option<bool> {
        let raw = std::fs::read_to_string(dir.join("queue/rotational")).ok()?;
        match raw.trim() {
            "1" => Some(true),
            "0" => Some(false),
            _ => None,
        }
    };
    read(&sys).or_else(|| read(sys.parent()?))
}

#[cfg(not(target_os = "linux"))]
pub(super) fn rotational(_path: &Path) -> Option<bool> {
    None
}

/// Core count at or below which a box is treated as NAS-class for the
/// rotational clamp.
pub(super) const NAS_CORES: usize = 4;

/// How many decode workers to run, given what the output sits on.
///
/// Decoded articles `pwrite` at their final offsets, so N decode workers
/// scatter N interleaved write streams across the output file: the
/// network's article lanes become the platter's seek lanes. One worker
/// keeps them in order.
///
/// Gated on THREE signals, because the clamp is only free on one side of
/// each. On a NAS-class box it costs nothing - measured flat from 1 to 4
/// decoders on Gracemont E-cores (the N100-class proxy), since this path
/// does not scale with decode workers there. On a big box it is NOT free
/// (1075 -> 3226 MB/s going 1 to 4 decoders on an M3 Ultra), and a
/// rotational device there is usually a wide array that can absorb the
/// parallel writes. `Unknown` never clamps, and neither does `Network`:
/// those mounts reported `Unknown` here until the variant was split out
/// on 3 Sep 2026 and this rule must not change under them.
///
/// **The third signal is [`StorageProbe::direct_dev`], and it is what
/// keeps this rule where its evidence is** (TODO 325, 4 Sep 2026).
/// Closing the anonymous-device hole in the probe made `Rotational`
/// newly VISIBLE on btrfs and ZFS, which would have handed this clamp
/// to every small btrfs NAS in one commit - a throughput change on a
/// population nobody has measured, and the fleet has no box with both a
/// rotational volume and few enough cores to measure it on (the one
/// spinning Linux box has twelve). The stand-down is not merely "not
/// measured", though: the sentence this clamp rests on is about WRITE
/// ORDER reaching the platter, and on the filesystems the fallback
/// reaches it does not - btrfs and ZFS copy on write, so the allocator
/// and not our `pwrite` offset decides where a block lands. So the
/// clamp asks for a class read off the filesystem's own device. An
/// operator who wants it anyway still has `NZBFAST_STORAGE=rotational`,
/// which asserts `direct_dev`.
pub fn decoders_for_storage(storage: StorageProbe, cores: usize, decoders: usize) -> usize {
    if decoders > 1
        && cores <= NAS_CORES
        && storage.class == Storage::Rotational
        && storage.direct_dev
    {
        1
    } else {
        decoders
    }
}
