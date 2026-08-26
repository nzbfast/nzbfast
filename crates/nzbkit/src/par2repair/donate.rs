//! §293 plan-side adoption: taking a WHOLE file off a failed
//! predecessor's disk before the successor's download plans a byte.
//!
//! # Why this is not the adoption scan next door
//!
//! [`super::adopt`] answers "where can the bytes of this MISSING BLOCK
//! be found", after a fetch, for a repair that would otherwise fail. It
//! is a rescue rung and it is measured as one: §293's own A/B is a
//! repair that goes Unrepairable -> Completed. What it can never do is
//! stop a download happening, because by the time a repair runs the
//! download has run.
//!
//! This asks the other question, at the only moment the answer can save
//! anything: given the successor's PAR2 set - fetched on its own, ahead
//! of the plan - is a member file ALREADY on disk somewhere, whole and
//! byte-exact? Every file that answers yes has all of its articles
//! struck out of the fetch plan.
//!
//! # WHOLE FILES ONLY, and the reason is arithmetic rather than taste
//!
//! Skipping an ARTICLE means proving the donor covers the decoded byte
//! range that article would have written, and an NZB states only
//! ENCODED segment sizes. yEnc encoding is not a fixed expansion - an
//! escaped byte costs two, a line break lands every 128 - so an
//! article's decoded offset is not knowable until its body arrives.
//! The bound that IS sound (decoded_end(i) <= encoded_cum(i+1)) only
//! ever certifies a PREFIX, which buys a handful of articles at the
//! head of one file.
//!
//! A whole file needs no offset arithmetic at all: the FileDesc packet
//! states its length and its MD5, so the file either IS the set's
//! member or it is not. And whole files are the shape the motivating
//! incident actually leaves behind - §282's founding job died on the
//! RECOVERY SET with the payload 97.5% intact, which is a volume set
//! whose members are nearly all complete. The partial remainder keeps
//! its existing answer one phase later, in the repair's own scan.
//!
//! # The bar
//!
//! Length, then the FileDesc's first-16k MD5, then its whole-file MD5 -
//! the same ladder [`super::adopt::adopt_blocks`]'s whole-file fast
//! path climbs, and the same digests the repair engine trusts. A
//! repack-shaped donor (same names, same lengths, different bytes) is
//! refused by the third rung and donates nothing, which is the property
//! `a_donor_with_wrong_bytes_donates_nothing_and_changes_nothing`
//! pinned for the repair-time arm and this module's own tests pin here.

use super::adopt::md5_of_file;
use crate::par2::Par2Set;
use std::path::{Path, PathBuf};

/// One member file taken off a donor, named as the SET names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Donation {
    /// The PAR2 FileDesc name, as written into `out_dir` (sanitized).
    pub name: String,
    /// The member's declared length - the file on disk is exactly this.
    pub length: u64,
    /// Where the bytes came from, for the log.
    pub from: PathBuf,
}

/// Every regular non-`.par2` file in `dir`, with its length. An
/// unreadable directory donates nothing and is NOT an error: a donor is
/// a directory this job does not own, and a racing retention sweep or a
/// user delete must degrade to "no donation", never to a failed job.
/// Same ownership rule as [`super::adopt`]'s `adoption_candidates`, and
/// the same reason.
fn donor_files(dir: &Path) -> Vec<(PathBuf, u64)> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.extension()
            .is_some_and(|x| x.eq_ignore_ascii_case("par2"))
        {
            continue;
        }
        let Ok(meta) = e.metadata() else { continue };
        if !meta.is_file() || meta.len() == 0 {
            continue;
        }
        out.push((p, meta.len()));
    }
    // Deterministic, so which of two byte-identical donors is credited
    // in the log does not depend on the filesystem's readdir order.
    out.sort();
    out
}

/// How many files the `donors` offer this pass at all - a plain
/// directory walk, no hashing.
///
/// The caller's pre-pass has to FETCH the successor's PAR2 index before
/// it can ask anything else, and that fetch is its whole cost. Asking
/// this first makes the cost zero for the two cases that offer nothing
/// to weigh it against: a donor directory that has already been swept,
/// and one that cannot be read at all.
pub fn donor_candidates(donors: &[PathBuf], out_dir: &Path) -> usize {
    donors
        .iter()
        .filter(|d| d.as_path() != out_dir)
        .map(|d| donor_files(d).len())
        .sum()
}

/// Find whole members of `set` on the `donors` and put them in
/// `out_dir` under the set's own names.
///
/// Returns one [`Donation`] per file placed, in set order. A member
/// already present in `out_dir` at the right length and MD5 is reported
/// too and copied nowhere - a re-run of the same switch must be a
/// no-op, not a second copy.
///
/// COPIES rather than links. A hardlink would make the successor's
/// output and the predecessor's the same inode, so the extractor's
/// spent-source cleanup, a repair patch or a user delete on either side
/// would reach through into the other; the whole point of §293's
/// `consumed_sources` rule is that a donor's payload is never handed to
/// the caller's delete. The copy is local I/O standing in for a
/// download of the same bytes, which is the trade.
///
/// A copy that fails (no space, a vanished donor, a read error) drops
/// THAT file and keeps going: the fetch plan simply keeps the articles
/// it would have struck out, which is exactly today's behaviour.
pub fn donate_whole_files(set: &Par2Set, donors: &[PathBuf], out_dir: &Path) -> Vec<Donation> {
    let mut placed = Vec::new();
    if set.files.is_empty() {
        return placed;
    }
    let cands: Vec<(PathBuf, u64)> = donors
        .iter()
        .filter(|d| d.as_path() != out_dir)
        .flat_map(|d| donor_files(d))
        .collect();
    // Nothing to offer: leave without hashing a byte of `out_dir`.
    if cands.is_empty() {
        return placed;
    }
    // One MD5 per candidate at most, however many members probe it - a
    // renamed multi-volume set pairs N members with N candidates, and
    // without the caches that is N^2 passes over the payload.
    let mut head_cache: Vec<Option<[u8; 16]>> = vec![None; cands.len()];
    let mut whole_cache: Vec<Option<[u8; 16]>> = vec![None; cands.len()];
    let mut taken = vec![false; cands.len()];
    for f in &set.files {
        if f.length == 0 {
            continue;
        }
        let name = crate::disk::sanitize_filename(&f.name);
        let dest = out_dir.join(&name);
        // Already here and already right (a re-run, or the fetch of a
        // previous attempt): report it, copy nothing.
        if std::fs::metadata(&dest).is_ok_and(|m| m.is_file() && m.len() == f.length)
            && md5_of_file(&dest, Some(f.length.min(16384))).is_ok_and(|h| h == f.md5_16k)
            && md5_of_file(&dest, None).is_ok_and(|h| h == f.md5)
        {
            placed.push(Donation {
                name,
                length: f.length,
                from: dest,
            });
            continue;
        }
        // A destination that exists and is NOT the member is left
        // alone: an in-progress fetch owns that inode, and overwriting
        // it is how a donation turns into corruption.
        if dest.exists() {
            continue;
        }
        for (ci, (p, len)) in cands.iter().enumerate() {
            if taken[ci] || *len != f.length {
                continue;
            }
            let head = match head_cache[ci] {
                Some(h) => h,
                None => match md5_of_file(p, Some((*len).min(16384))) {
                    Ok(h) => {
                        head_cache[ci] = Some(h);
                        h
                    }
                    // Unreadable or vanished since the walk: drop the
                    // candidate for good, never fail the job.
                    Err(_) => {
                        taken[ci] = true;
                        continue;
                    }
                },
            };
            if head != f.md5_16k {
                continue;
            }
            let whole = match whole_cache[ci] {
                Some(h) => h,
                None => match md5_of_file(p, None) {
                    Ok(h) => {
                        whole_cache[ci] = Some(h);
                        h
                    }
                    Err(_) => {
                        taken[ci] = true;
                        continue;
                    }
                },
            };
            if whole != f.md5 {
                continue;
            }
            // Into a temporary beside the destination and then renamed,
            // so a copy interrupted half way never leaves a
            // right-named, wrong-length file for the verify to find and
            // condemn.
            let tmp = out_dir.join(format!(".{name}.donating"));
            let _ = std::fs::remove_file(&tmp);
            if std::fs::copy(p, &tmp).is_err() || std::fs::rename(&tmp, &dest).is_err() {
                let _ = std::fs::remove_file(&tmp);
                break;
            }
            taken[ci] = true;
            placed.push(Donation {
                name: name.clone(),
                length: f.length,
                from: p.clone(),
            });
            break;
        }
    }
    placed
}
