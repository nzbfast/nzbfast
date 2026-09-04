//! The mount table as a SECOND route from a path to its block device.
//!
//! [`super::rotational`] indexes `/sys/dev/block` with the filesystem's
//! own `st_dev`, and a whole family of filesystems has no `st_dev` to
//! index with: btrfs, ZFS and overlayfs allocate an ANONYMOUS block
//! device (`major 0`), so the sysfs path does not exist and the probe
//! answers `None`. This module is the fallback that finds the device
//! anyway, by asking the kernel which device the path's MOUNT was made
//! from.
//!
//! Three things were measured on 4 Sep 2026 before this was written,
//! because each of them would have silently broken an obvious design:
//!
//! * **`st_dev` and mountinfo's own `major:minor` DISAGREE on btrfs**,
//!   so an entry cannot be found by matching the device id. Every btrfs
//!   SUBVOLUME gets its own anonymous device while the mountinfo line
//!   carries the superblock's: on the fleet's NAS `/volume1` stats as
//!   `0:40` and its mountinfo line says `0:34`, and a two-device loop
//!   btrfs on the Zen 4 stats as `0:52` against a line saying `0:48`.
//!   The match here is therefore by MOUNT POINT, longest prefix wins.
//! * **A container's `/dev` carries no block devices at all** (measured
//!   inside `debian:bookworm`: `/dev` is a 64 MB tmpfs holding `null`,
//!   `zero`, `pts` and friends), so `stat`ing the source path is not
//!   enough on the one platform this fallback most wants to serve. The
//!   kernel NAME still resolves under `/sys/class/block`, which is a
//!   real read-only sysfs inside a container, and that is the second
//!   route in [`block_name_for_source`].
//! * **The source is not always a plain disk name.** The NAS mounts
//!   `/dev/mapper/cachedev_0`, a device-mapper node whose basename is
//!   absent from `/sys/class/block` (the kernel calls it `dm-3`); only
//!   the `stat` route resolves it. Both routes are needed, neither is
//!   sufficient.
//!
//! Everything here fails CLOSED, per the rule at [`super::rotational`]:
//! any step that cannot answer returns `None`, which is
//! `Storage::Unknown`, which selects no aggressive arm anywhere.

use std::path::Path;

/// The kernel's per-process mount table. `/proc/self/mounts` would not
/// do: it carries neither the mount id fields nor the optional-field
/// separator this parser keys on, and mountinfo is the only one that
/// names a bind mount's source device.
const MOUNTINFO: &str = "/proc/self/mountinfo";

/// The rotational flag of the device `path`'s mount was made from, or
/// `None` when any step of the walk cannot answer.
///
/// Only ever consulted after the direct `st_dev` route has already
/// failed, so the common case (ext4, xfs, APFS, NTFS) never reads the
/// mount table at all.
///
/// Compiled on every unix and useful on exactly one: `read` of a file
/// that does not exist is how macOS and the BSDs answer `None` here,
/// which keeps the parser below live code - and therefore tested - on
/// the platform this repo's sessions actually run on.
pub(super) fn rotational_via_mount_table(path: &Path) -> Option<bool> {
    let real = std::fs::canonicalize(path).ok()?;
    // Lossy rather than `read_to_string`: one exotic mount point
    // elsewhere in the table must not blind the probe for the path we
    // were asked about. A mangled entry simply fails to match.
    let raw = std::fs::read(MOUNTINFO).ok()?;
    let source = mount_source_for(&String::from_utf8_lossy(&raw), &real)?;
    rotational_of_source(Path::new(&source))
}

/// The mount SOURCE of the deepest mount point that contains `path`.
///
/// Longest prefix wins, and a LATER line wins a tie: mountinfo is in
/// mount order, and a mount made over an existing mount point shadows
/// it for every lookup after that.
fn mount_source_for(table: &str, path: &Path) -> Option<String> {
    let mut best: Option<(usize, &str)> = None;
    for line in table.lines() {
        let Some((point, source)) = mount_point_and_source(line) else {
            continue;
        };
        let point = unescape(point);
        let Some(depth) = prefix_depth(&point, path) else {
            continue;
        };
        if best.is_none_or(|(d, _)| depth >= d) {
            best = Some((depth, source));
        }
    }
    best.map(|(_, s)| unescape(s))
}

/// `(mount point, mount source)` out of one mountinfo line, or `None`
/// for a line this parser cannot read - which is skipped rather than
/// taken as an answer.
///
/// The layout is fixed by `Documentation/filesystems/proc.rst`: five
/// fields, then per-mount options, then a VARIABLE number of optional
/// fields, then a lone `-`, then the filesystem type, the source and
/// the super options. The optional fields are why the tail cannot be
/// indexed from the front and the separator has to be found.
fn mount_point_and_source(line: &str) -> Option<(&str, &str)> {
    let mut f = line.split(' ');
    let point = f.nth(4)?;
    f.find(|t| *t == "-")?;
    let _fstype = f.next()?;
    let source = f.next()?;
    Some((point, source))
}

/// How many path components `point` has, when it is a component-wise
/// prefix of `path`; `None` when it is not one.
///
/// `Path::starts_with` and not a string prefix, so `/tmp/ab` does not
/// count as a mount point of `/tmp/abc`.
fn prefix_depth(point: &str, path: &Path) -> Option<usize> {
    let point = Path::new(point);
    path.starts_with(point).then(|| point.components().count())
}

/// Undo the kernel's `mangle_path`, which escapes EXACTLY four bytes -
/// space, tab, newline and backslash - as three-digit octal.
///
/// Restricted to those four on purpose: a general octal decoder would
/// have to answer what `\351` means in a `str`, and the kernel never
/// emits it. Anything else is copied through, so an unrecognised escape
/// leaves a path that simply fails to match rather than one silently
/// rewritten.
fn unescape(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('\\') {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        let decoded = match tail.get(..4) {
            Some("\\040") => Some(' '),
            Some("\\011") => Some('\t'),
            Some("\\012") => Some('\n'),
            Some("\\134") => Some('\\'),
            _ => None,
        };
        match decoded {
            Some(c) => {
                out.push(c);
                rest = &tail[4..];
            }
            None => {
                out.push('\\');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// The rotational flag of the block device a mount source names, folded
/// over every member of the filesystem this crate can see.
///
/// **ANY member rotational means rotational, and that is a stated
/// choice.** A filesystem spanning both kinds of device is a real
/// configuration (a btrfs pool with an SSD added to it), and every
/// reader of `Storage` treats `Rotational` as the side that arms
/// nothing and stands things down - so a disagreement resolves to the
/// answer that cannot cost throughput it has not measured. The
/// alternative, standing down to `Unknown` on a split verdict, throws
/// away a correct answer for the overwhelmingly common case where the
/// members agree.
#[cfg(target_os = "linux")]
fn rotational_of_source(source: &Path) -> Option<bool> {
    let name = block_name_for_source(source)?;
    let members = btrfs_members(&name).unwrap_or_else(|| vec![name]);
    let mut seen = None;
    for m in members {
        match super::sysfs_rotational(Path::new("/sys/class/block").join(m)) {
            Some(true) => return Some(true),
            Some(false) => seen = Some(false),
            None => {}
        }
    }
    seen
}

#[cfg(not(target_os = "linux"))]
fn rotational_of_source(_source: &Path) -> Option<bool> {
    None
}

/// The kernel's own name (`sda1`, `dm-3`, `loop0`) for whatever a mount
/// source string names, by two routes - see the module doc for why one
/// is not enough.
///
/// A source that resolves through NEITHER is the stand-down this
/// fallback is most often going to take, and it is the right answer:
/// `overlay`, a ZFS dataset name like `tank/media` and `tmpfs` are all
/// sources with no block device under them at all. Overlayfs in
/// particular cannot be resolved from inside a container even in
/// principle - its `upperdir=` names a path in the HOST's filesystem
/// (measured: `/var/lib/containerd/...`, absent inside the container) -
/// so it is left alone here rather than half-handled.
#[cfg(target_os = "linux")]
fn block_name_for_source(source: &Path) -> Option<String> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    if source.is_absolute()
        && let Ok(m) = std::fs::metadata(source)
        && m.file_type().is_block_device()
    {
        let rdev = m.rdev();
        // libc::major/minor are safe fns on Linux - see the same note at
        // `disk::rotational`, which an `unsafe` block here would trip.
        let (major, minor) = (libc::major(rdev), libc::minor(rdev));
        if let Ok(p) = std::fs::canonicalize(format!("/sys/dev/block/{major}:{minor}"))
            && let Some(name) = p.file_name().and_then(|n| n.to_str())
        {
            return Some(name.to_owned());
        }
    }
    let name = source.file_name()?.to_str()?;
    Path::new("/sys/class/block")
        .join(name)
        .exists()
        .then(|| name.to_owned())
}

/// Every device of the btrfs filesystem `name` belongs to, or `None`
/// when it belongs to none - which is every other filesystem.
///
/// btrfs is the one multi-device filesystem this fallback can survey
/// rather than sample: mountinfo names only the device the mount was
/// made from, but `/sys/fs/btrfs/<fsid>/devices/` lists them all.
/// Verified present on both ends of the range this repo runs on -
/// kernel 6.8 on the Zen 4 (`loop0`, `loop1` for a two-device pool) and
/// the NAS's DSM kernel 4.4 (`dm-3`, `dm-4`).
///
/// ZFS has no equivalent, so a ZFS pool stands down at
/// [`block_name_for_source`] before reaching here.
#[cfg(target_os = "linux")]
fn btrfs_members(name: &str) -> Option<Vec<String>> {
    for fs in std::fs::read_dir("/sys/fs/btrfs").ok()?.flatten() {
        let devices = fs.path().join("devices");
        if !devices.join(name).exists() {
            continue;
        }
        let all: Vec<String> = std::fs::read_dir(&devices)
            .ok()?
            .flatten()
            .filter_map(|e| e.file_name().to_str().map(str::to_owned))
            .collect();
        return (!all.is_empty()).then_some(all);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two real lines, byte for byte, from the boxes this fallback was
    /// written against: the NAS's btrfs `/volume1` on a device-mapper
    /// node, and a container's bind-mounted `/downloads`. The parser
    /// has to reach past a variable number of optional fields (the
    /// `shared:474` / `master:1` tags) to find the source.
    #[test]
    fn mountinfo_lines_yield_their_point_and_source() {
        let nas = "39 18 0:34 /@syno /volume1 rw,nodev,relatime - btrfs \
                   /dev/mapper/cachedev_0 rw,ssd,synoacl,subvol=/@syno";
        assert_eq!(
            mount_point_and_source(nas),
            Some(("/volume1", "/dev/mapper/cachedev_0"))
        );
        let bind = "622 607 8:1 /tmp/probe-bind /downloads rw,relatime \
                    master:1 - ext4 /dev/sda1 rw,discard,errors=remount-ro";
        assert_eq!(
            mount_point_and_source(bind),
            Some(("/downloads", "/dev/sda1"))
        );
        // No separator, too few fields, empty: skipped, never guessed at.
        assert_eq!(mount_point_and_source("39 18 0:34 / /volume1 rw"), None);
        assert_eq!(mount_point_and_source("39 18 0:34"), None);
        assert_eq!(mount_point_and_source(""), None);
    }

    /// The deepest mount containing the path wins, and a mount point
    /// that is only a STRING prefix does not count.
    #[test]
    fn deepest_mount_point_wins_and_prefixes_are_component_wise() {
        let table = "\
1 0 0:1 / / rw - ext4 /dev/sda1 rw
2 1 0:2 / /volume1 rw - btrfs /dev/mapper/cachedev_0 rw
3 1 0:3 / /volume10 rw - btrfs /dev/mapper/cachedev_9 rw
4 2 0:4 / /volume1/backup rw - btrfs /dev/mapper/cachedev_1 rw
";
        let src = |p: &str| mount_source_for(table, Path::new(p));
        assert_eq!(
            src("/volume1/Movies/a.mkv").as_deref(),
            Some("/dev/mapper/cachedev_0")
        );
        assert_eq!(
            src("/volume1/backup/x").as_deref(),
            Some("/dev/mapper/cachedev_1")
        );
        // `/volume1` is not a mount point of `/volume10`.
        assert_eq!(
            src("/volume10/x").as_deref(),
            Some("/dev/mapper/cachedev_9")
        );
        assert_eq!(src("/etc/hosts").as_deref(), Some("/dev/sda1"));
        // Nothing contains a relative path, and nothing is not an answer.
        assert_eq!(src("relative/path"), None);
        assert_eq!(mount_source_for("", Path::new("/x")), None);
    }

    /// A mount made OVER an existing point shadows it, so the later
    /// line wins the tie at equal depth.
    #[test]
    fn a_later_mount_at_the_same_point_shadows_the_earlier_one() {
        let table = "\
1 0 0:1 / /data rw - ext4 /dev/sda1 rw
2 0 0:2 / /data rw - btrfs /dev/sdb1 rw
";
        assert_eq!(
            mount_source_for(table, Path::new("/data/x")).as_deref(),
            Some("/dev/sdb1")
        );
    }

    /// The kernel escapes exactly four bytes; everything else is copied
    /// through untouched rather than decoded on a guess.
    #[test]
    fn only_the_four_mangled_bytes_are_unescaped() {
        assert_eq!(unescape("/mnt/my\\040disk"), "/mnt/my disk");
        assert_eq!(unescape("/a\\011b\\012c\\134d"), "/a\tb\nc\\d");
        assert_eq!(unescape("/plain/path"), "/plain/path");
        assert_eq!(unescape("/a\\351b"), "/a\\351b", "not a mangled byte");
        assert_eq!(unescape("/trailing\\"), "/trailing\\");
        // And it survives a mount point that really does carry a space.
        let table = "1 0 0:1 / /mnt/my\\040disk rw - btrfs /dev/sdc1 rw\n";
        assert_eq!(
            mount_source_for(table, Path::new("/mnt/my disk/x")).as_deref(),
            Some("/dev/sdc1")
        );
    }

    /// The whole walk, on whatever this box is. It must never panic and
    /// must never answer for a path that does not exist - the answer
    /// itself is a property of the machine and cannot be asserted, which
    /// is why the evidence for this arm is the `readpolicy_probe` runs
    /// recorded in `research/STORAGE-PROBE-ANON-DEV-2026-09-04.md`.
    #[test]
    fn the_walk_is_total_and_refuses_a_missing_path() {
        assert_eq!(
            rotational_via_mount_table(Path::new("/nonexistent-nzbfast-mounttab")),
            None
        );
        let _ = rotational_via_mount_table(Path::new("."));
    }
}
