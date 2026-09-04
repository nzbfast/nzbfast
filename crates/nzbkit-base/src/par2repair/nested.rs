//! How far packet discovery may look below the directory it is handed
//! (Wave-4 row W4-06, 30 Aug 2026).
//!
//! PAR2 FileDesc publication preserves a safe relative path since the
//! relpath-preserve ruling (`crate::disk::sanitize_out_name`), so an
//! outer recovery set can legitimately land its inner packet files at
//! `META/inner.par2`. Every packet walk in this crate was a single
//! top-level `read_dir`, so the par2-of-par2 chain broke exactly there:
//! the outer set published `META/inner.par2` and all its volumes
//! correctly, the hash-named payload sat unclaimed at the job root, the
//! late-set trigger fired - and `disk_set_ids` saw only the outer set's
//! own packets, so the inner set that names the payload was never
//! applied. Measured on the `wave4-verify` probe branch: rc=0 with the
//! payload still hash-named.
//!
//! Recursion is OPT-IN and not the new default, deliberately. The other
//! packet walks are not asking the same question: the nested disk
//! post-pass leans on "an outer index whose volumes never touched this
//! dir has no FileDesc name on disk" to skip it, and the no-set
//! obfuscated arm's renamed fallback will attempt EVERY set it can see
//! and recreate that set's files from slices - so a set discovered
//! inside an extracted subdirectory would be repaired against the job
//! ROOT, which is not where its files live. Widening those is a
//! separate judgement with its own measurements; widening the late-set
//! door is this one.
//!
//! The containment rules W4-06 asks to keep are all here rather than at
//! the call sites: bounded depth, bounded directories and entries,
//! bounded bytes admitted from below the root, and no symlinked
//! directory ever descended into - which also settles path escape,
//! since every path this yields is built by pushing a `read_dir` entry
//! name onto a directory the walk already holds.

use super::{MAX_PACKET_FILE_BYTES, RepairError};
use std::path::{Path, PathBuf};
use tracing::warn;

/// How far a packet walk may look below the directory it is given.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum PacketScope {
    /// The directory itself and nothing under it - the historical walk,
    /// and still what every entry point that does not say otherwise
    /// gets.
    #[default]
    Flat,
    /// The directory plus safe subdirectories, bounded by the constants
    /// in this module. For discovering a recovery set that publication
    /// legitimately placed in a tree.
    Nested,
}

/// Deepest subdirectory a nested packet walk descends into. A published
/// tree is 2-3 deep (`sanitize_out_name` itself allows 16 components);
/// this is the walk's own patience, not a statement about legal names.
pub const MAX_NESTED_DEPTH: usize = 6;

/// Most directories one nested walk opens, root included. A job
/// directory is not a filesystem, and a post that builds thousands of
/// directories has already told you it is not a release.
pub const MAX_NESTED_DIRS: usize = 512;

/// Most directory entries one nested walk considers, across every
/// directory it opens.
pub const MAX_NESTED_ENTRIES: usize = 100_000;

/// Most packet-file bytes a nested walk admits FROM BELOW THE ROOT.
/// The root's own contribution is unbounded in total, exactly as the
/// flat walk always was - only the newly reachable namespace carries a
/// cumulative cap, so this can never change what a flat walk found.
/// One inner recovery set is a few MB; this is four orders above that.
pub const MAX_NESTED_BYTES: u64 = 4 << 30;

/// One candidate file a packet walk should consider, with the stat the
/// walk already paid for.
pub struct Candidate {
    pub path: PathBuf,
    pub meta: std::fs::Metadata,
}

/// Every SUBDIRECTORY of `dir` that the NESTED walk actually reached
/// and found a regular file in, sorted and deduplicated.
///
/// For a caller that has to let something ELSE look exactly as far as
/// this walk does. Wave-4 row M4-102 is the case it was written for:
/// `get::latesets` widened its unclaimed-file test to the tree (W4-06)
/// without widening the adoption scan behind it, so a late set could be
/// reached over a leftover the repair then could not find - and since
/// W4-01 a vouched set's denial FAILS the job, which turned a job that
/// used to finish into one that does not.
///
/// Derived from the SAME walk [`walk_candidates`] uses rather than from
/// a second one, and that is the whole point rather than an economy:
/// depth, the symlink rule, the directory cap and the entry cap are
/// decided in ONE place, so a caller cannot end up reaching further -
/// or less far - than the walk that armed it. A second walk beside this
/// one is the copy-paste sibling that agrees today and drifts later.
///
/// The BYTE budget is the one bound deliberately NOT taken, and it was
/// taken for a day. [`MAX_NESTED_BYTES`] bounds what a packet walk might
/// LOAD; this returns paths and loads nothing, and `get::latesets`'
/// `has_unclaimed` - the door this exists to keep pace with - has no
/// byte bound either, so charging it here made the reach SHORTER than
/// the door on exactly the trees that matter. Measured 31 Aug 2026:
/// five files over [`MAX_PACKET_FILE_BYTES`] in one subdirectory - an
/// ordinary season pack, and they charge at the per-file ceiling rather
/// than their real size - exhaust the 4 GiB budget, and the NEXT
/// subdirectory is never returned. With the leftover in that one, the
/// late-set repair cannot reach it, the vouched set denies, and the job
/// FAILS: M4-102's own defect, one level down, in the fix for it.
///
/// A directory holding no regular file is not returned. That is not a
/// gap: every caller so far wants somewhere to read bytes FROM, and an
/// empty directory offers none.
pub fn nested_subdirs(dir: &Path) -> Result<Vec<PathBuf>, RepairError> {
    let mut out: Vec<PathBuf> = walk_files(dir, PacketScope::Nested)?
        .into_iter()
        .filter_map(|c| c.path.parent().map(Path::to_path_buf))
        .filter(|p| p != dir)
        .collect();
    out.sort();
    out.dedup();
    Ok(out)
}

/// Every regular file a packet walk may consider under `dir`, sorted by
/// entry name within each directory. `Flat` is one `read_dir` and is
/// byte-for-byte the historical set. `Nested` adds safe subdirectories
/// under the module's budgets, breadth-first so a shallow tree is
/// complete before a deep one can spend the budget.
///
/// SORTED PER DIRECTORY since 31 Aug 2026, and what that is for is
/// narrower than it looks - every caller today already sorts what it
/// takes from here (`nested_subdirs` above, `collect::packet_files`,
/// `PacketCatalog::relist`), so set discovery order was ALREADY
/// deterministic and this changes none of it. What was not
/// deterministic is WHICH entries survive `MAX_NESTED_ENTRIES`: the cap
/// truncates the walk mid-directory, and in raw `read_dir` order the
/// surviving set is a filesystem hash order, so an over-budget
/// directory could hand two runs of the same job different packet
/// files. Sorting decides that the same way twice. Reading the
/// directory into memory first is bounded by the same constant that
/// bounds the walk - the collect stops at the remaining budget - so it
/// can never hold more entries than the walk was already going to
/// consider.
///
/// Symlinks - to files as well as directories - are skipped, which is
/// the `is_file()` / `is_dir()` test on a `read_dir` entry's own file
/// type (an `lstat`, never followed). A symlinked directory is
/// therefore never descended into, so no yielded path can leave `dir`.
///
/// An unreadable subdirectory is skipped, never fatal: a job directory
/// can hold anything, and one unreadable corner must not cost the
/// caller the sets it CAN see. Only `dir` itself failing to open is an
/// error, which is what the flat walk always reported.
pub fn walk_candidates(dir: &Path, scope: PacketScope) -> Result<Vec<Candidate>, RepairError> {
    walk(dir, scope, true)
}

/// [`walk_candidates`] for a caller that reads PAYLOAD rather than
/// packets: the same walk, the same depth, directory, entry and symlink
/// rules, with the cumulative BYTE budget NOT charged.
///
/// The second door onto `charge_bytes = false` rather than a second
/// walk, for [`nested_subdirs`]' reason - depth, the symlink rule and
/// the two count caps have to be decided in ONE place or two callers
/// end up reaching different distances into the same tree.
///
/// WHY THE BYTE BUDGET IS WRONG HERE, since it is the one bound this
/// drops. [`MAX_NESTED_BYTES`] bounds what a PACKET walk might load,
/// and it charges each file at [`MAX_PACKET_FILE_BYTES`] rather than at
/// its real size - a proxy calibrated for index and volume files. An
/// adoption scan's candidates are the payload itself, so on exactly the
/// trees the relpath-preserve ruling created (a `VIDEO_TS` set, a
/// season pack) a handful of members exhaust 4 GiB and the NEXT
/// subdirectory - which is where the file being looked for may well be
/// - is never returned. That is [`nested_subdirs`]' own measurement of
/// 31 Aug 2026, and the flat walk this replaces charged nothing at all,
/// so charging here would make the reach SHORTER than the scan it
/// widens. What actually bounds the work is the entry and directory
/// caps, which are unconditional.
pub fn walk_files(dir: &Path, scope: PacketScope) -> Result<Vec<Candidate>, RepairError> {
    walk(dir, scope, false)
}

/// The nested [`walk_files`] set as `(path, length)`, for a caller
/// OUTSIDE this crate.
///
/// `nzbfast::repair::adoption_candidates_present` is the one that needs
/// it. That gate exists to PREDICT what
/// `par2repair::adopt::adoption_candidates` will find, and for a few
/// hours on 31 Aug 2026 it did not: X6-02 widened the engine and left
/// the predicate flat, so the gate answered NO on a tree where the
/// engine would have found a candidate - and its NO is an arm of
/// `shortfall_is_final`, which can take the give-up branch without ever
/// reaching the probe that would have found the bytes. A predicate that
/// walks a different set from the walk it predicts is worse than no
/// predicate. Sharing the walk is what stops the two answering
/// different questions; the gate's own screens - a declared name, a
/// wrong length - are its business and stay there.
pub fn source_candidate_files(dir: &Path) -> Result<Vec<(PathBuf, u64)>, RepairError> {
    Ok(walk_files(dir, PacketScope::Nested)?
        .into_iter()
        .map(|c| (c.path, c.meta.len()))
        .collect())
}

/// [`walk_candidates`], with the cumulative BYTE budget as a parameter.
///
/// `charge_bytes` is false for a caller that only wants to know WHERE
/// things are and will not read any of them. [`MAX_NESTED_BYTES`] bounds
/// what a packet walk might LOAD, so charging it against a caller that
/// loads nothing does not protect anything - it just makes that caller
/// see less of the tree than the walk's own depth, directory and entry
/// bounds allow. M4-102 measured what that costs when the caller is
/// [`nested_subdirs`]: five files over [`MAX_PACKET_FILE_BYTES`] in one
/// subdirectory - an ordinary season pack - exhaust the budget, and the
/// NEXT subdirectory, which is where the leftover was, is never
/// reported. Depth, directories, entries and the symlink rule are
/// unchanged either way, which is what keeps the two callers agreeing
/// about how far "here" reaches.
fn walk(dir: &Path, scope: PacketScope, charge_bytes: bool) -> Result<Vec<Candidate>, RepairError> {
    let mut out: Vec<Candidate> = Vec::new();
    let mut queue: std::collections::VecDeque<(PathBuf, usize)> = std::collections::VecDeque::new();
    queue.push_back((dir.to_path_buf(), 0));
    let mut dirs_opened = 0usize;
    let mut entries_seen = 0usize;
    let mut nested_bytes = 0u64;
    let mut budget_hit = false;
    while let Some((d, depth)) = queue.pop_front() {
        let root = depth == 0;
        let rd = match std::fs::read_dir(&d) {
            Ok(rd) => rd,
            Err(e) if root => return Err(e.into()),
            Err(_) => continue,
        };
        dirs_opened += 1;
        // Listed, then sorted, then walked - see the header. `break`
        // rather than `continue` on the cap keeps the historical
        // semantics: the walk stops, it does not skip ahead.
        let mut ents: Vec<std::fs::DirEntry> = Vec::new();
        for e in rd {
            let Ok(e) = e else { continue };
            entries_seen += 1;
            if entries_seen > MAX_NESTED_ENTRIES {
                budget_hit = true;
                break;
            }
            ents.push(e);
        }
        ents.sort_by_key(std::fs::DirEntry::file_name);
        for e in ents {
            // A `DirEntry`'s own file type is an `lstat` - std
            // guarantees it never traverses a symlink - so a symlinked
            // DIRECTORY is neither `is_dir()` (never descended) nor
            // `is_file()` (never yielded), and a symlinked FILE is not
            // `is_file()` either. That is the whole no-escape argument
            // and the flat walk's historical behavior both; an explicit
            // `is_symlink()` arm on top would be a second guard that
            // makes neither falsifiable.
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                if scope == PacketScope::Nested
                    && depth < MAX_NESTED_DEPTH
                    && dirs_opened + queue.len() < MAX_NESTED_DIRS
                {
                    queue.push_back((e.path(), depth + 1));
                }
                continue;
            }
            if !ft.is_file() {
                continue;
            }
            let Ok(meta) = e.metadata() else { continue };
            if !root && charge_bytes {
                // Charge the nested budget by what a packet walk could
                // actually READ, so a subdirectory of huge non-packet
                // payload files does not spend the cap it exists to
                // protect. Anything past the per-file ceiling is
                // skipped by every consumer anyway.
                let chargeable = meta.len().min(MAX_PACKET_FILE_BYTES);
                if nested_bytes.saturating_add(chargeable) > MAX_NESTED_BYTES {
                    budget_hit = true;
                    continue;
                }
                nested_bytes += chargeable;
            }
            out.push(Candidate {
                path: e.path(),
                meta,
            });
        }
        if entries_seen > MAX_NESTED_ENTRIES {
            break;
        }
    }
    if budget_hit {
        warn!(
            dir = %dir.display(),
            dirs = dirs_opened,
            entries = entries_seen,
            nested_bytes,
            "nested packet discovery stopped at its budget - deeper files not considered"
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn names(dir: &Path, scope: PacketScope) -> HashSet<String> {
        walk_candidates(dir, scope)
            .expect("walk")
            .into_iter()
            .map(|c| crate::disk::out_name_of(dir, &c.path))
            .collect()
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("nzbfast-nested-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("mkdir");
        d
    }

    /// `Flat` is the historical walk: the root's own files and nothing
    /// below it, whatever is down there.
    #[test]
    fn flat_sees_the_root_only_and_nested_sees_the_tree() {
        let d = tmp("flatvsnested");
        std::fs::write(d.join("root.par2"), b"x").unwrap();
        std::fs::create_dir_all(d.join("META/deeper")).unwrap();
        std::fs::write(d.join("META/inner.par2"), b"x").unwrap();
        std::fs::write(d.join("META/deeper/vol.par2"), b"x").unwrap();
        assert_eq!(
            names(&d, PacketScope::Flat),
            HashSet::from(["root.par2".to_string()])
        );
        assert_eq!(
            names(&d, PacketScope::Nested),
            HashSet::from([
                "root.par2".to_string(),
                "META/inner.par2".to_string(),
                "META/deeper/vol.par2".to_string(),
            ])
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// M4-102, the second cut: the byte budget must NOT bound a caller
    /// that reads nothing.
    ///
    /// Sparse files, so this costs no disk: `meta.len()` is what the
    /// walk charges and it reports the apparent size. Five 2 GiB files
    /// in `disc1` charge at `MAX_PACKET_FILE_BYTES` each, which is 5 GiB
    /// against a 4 GiB budget - so under the charging walk `disc2` is
    /// never reached, and `disc2` is where the leftover is. That is the
    /// reach falling SHORT of the door, which has no byte bound at all,
    /// and it is the shape the whole M4-102 fix exists to refuse.
    ///
    /// Both arms are driven, because the point is the DIFFERENCE: the
    /// packet walk must still stop (it loads what it finds), and the
    /// directory walk must not.
    #[test]
    fn the_byte_budget_bounds_the_packet_walk_and_not_the_directory_walk() {
        let d = tmp("bytebudget");
        for (sub, n) in [("disc1", 5usize), ("disc2", 1usize)] {
            std::fs::create_dir_all(d.join(sub)).unwrap();
            for i in 0..n {
                let f = std::fs::File::create(d.join(sub).join(format!("f{i}.mkv"))).unwrap();
                f.set_len(2 << 30).unwrap();
            }
        }
        std::fs::write(d.join("disc2/Bq3fJm77ZsK.mkv"), b"leftover").unwrap();

        // The reach: every directory, budget or no budget.
        let got = nested_subdirs(&d).expect("subdirs");
        assert!(
            got.contains(&d.join("disc2")),
            "the directory holding the leftover must be reachable: {got:?}"
        );
        assert!(got.contains(&d.join("disc1")), "{got:?}");

        // The packet walk still stops, and stopping is what proves the
        // budget is live rather than quietly deleted.
        let charged = walk(&d, PacketScope::Nested, true).expect("walk");
        assert!(
            !charged.iter().any(|c| c.path.starts_with(d.join("disc2"))),
            "the CHARGING walk must still stop at its budget"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// M4-102: `nested_subdirs` reports the directories the nested walk
    /// REACHED, so a caller that must look exactly as far as this walk
    /// does has the list - never the root itself, never a directory with
    /// nothing in it to read, and never one past the walk's own bounds.
    ///
    /// The last of those is the property that matters and the reason
    /// this is derived from `walk_candidates` rather than written
    /// beside it: a second walk agreeing today is a second walk that
    /// drifts later, and this pair decides how far a repair may reach
    /// for bytes.
    #[test]
    fn nested_subdirs_are_the_directories_the_walk_actually_reached() {
        let d = tmp("subdirs");
        std::fs::write(d.join("root.par2"), b"x").unwrap();
        std::fs::create_dir_all(d.join("META/deeper")).unwrap();
        std::fs::create_dir_all(d.join("payload")).unwrap();
        std::fs::create_dir_all(d.join("empty")).unwrap();
        std::fs::write(d.join("META/inner.par2"), b"x").unwrap();
        std::fs::write(d.join("META/deeper/vol.par2"), b"x").unwrap();
        std::fs::write(d.join("payload/Bq3fJm77ZsK"), b"x").unwrap();
        let got = nested_subdirs(&d).expect("subdirs");
        assert_eq!(
            got,
            vec![d.join("META"), d.join("META/deeper"), d.join("payload")],
            "sorted, deduplicated, no root and no empty directory"
        );
        // Past the walk's own depth bound there is nothing to offer,
        // which is the bound being INHERITED rather than restated.
        let deep = d.join("chain");
        let mut p = deep.clone();
        for i in 0..=(MAX_NESTED_DEPTH + 2) {
            p = p.join(format!("d{i}"));
        }
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(p.join("late.par2"), b"x").unwrap();
        let got = nested_subdirs(&d).expect("subdirs");
        assert!(
            !got.contains(&p),
            "a directory the walk cannot reach must not be offered: {got:?}"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The depth bound holds, and it is a bound on the WALK and not an
    /// error: what is inside reach still comes back.
    #[test]
    fn the_depth_bound_stops_the_descent_without_losing_the_shallow_files() {
        let d = tmp("depth");
        let mut p = d.clone();
        for i in 0..=(MAX_NESTED_DEPTH + 2) {
            p = p.join(format!("d{i}"));
            std::fs::create_dir_all(&p).unwrap();
            std::fs::write(p.join("f.par2"), b"x").unwrap();
        }
        let got = names(&d, PacketScope::Nested);
        assert_eq!(got.len(), MAX_NESTED_DEPTH, "{got:?}");
        assert!(got.contains("d0/f.par2"), "{got:?}");
        assert!(
            !got.iter()
                .any(|n| n.contains(&format!("d{MAX_NESTED_DEPTH}"))),
            "walked past the depth bound: {got:?}"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A symlinked directory is never descended into, and a symlinked
    /// file is never yielded - which is what keeps every path this
    /// returns inside `dir`. The escape target is a real directory with
    /// a real packet-shaped file in it, so a walk that reached for
    /// `Path::is_dir` (which DOES traverse) instead of the entry's own
    /// `lstat` file type shows it. Verified to bite that way.
    #[cfg(unix)]
    #[test]
    fn symlinks_are_not_followed_so_nothing_escapes_the_directory() {
        let d = tmp("symlink");
        let outside = tmp("symlink-outside");
        std::fs::write(outside.join("escaped.par2"), b"x").unwrap();
        std::fs::write(d.join("kept.par2"), b"x").unwrap();
        std::os::unix::fs::symlink(&outside, d.join("link")).unwrap();
        std::os::unix::fs::symlink(outside.join("escaped.par2"), d.join("linked.par2")).unwrap();
        let got = names(&d, PacketScope::Nested);
        assert_eq!(got, HashSet::from(["kept.par2".to_string()]), "{got:?}");
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// A missing root is the caller's error (the flat walk always
    /// reported it); an unreadable corner deeper down is not, because
    /// one bad subdirectory must not cost the caller the sets it can
    /// see.
    #[test]
    fn a_missing_root_errors_and_a_missing_subdirectory_does_not() {
        let d = tmp("missing");
        assert!(walk_candidates(&d.join("nope"), PacketScope::Nested).is_err());
        std::fs::write(d.join("kept.par2"), b"x").unwrap();
        std::fs::create_dir_all(d.join("gone")).unwrap();
        std::fs::write(d.join("gone/x.par2"), b"x").unwrap();
        // Racing the walk is what this models; removing it up front is
        // the deterministic stand-in for the same read_dir failure.
        std::fs::remove_dir_all(d.join("gone")).unwrap();
        assert_eq!(
            names(&d, PacketScope::Nested),
            HashSet::from(["kept.par2".to_string()])
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
