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
//!
//! And then a fourth rung the first three cannot stand in for: the copy
//! is hashed AS IT IS COPIED, and renamed into place only if the bytes
//! that moved are the member's. The three above judge a read that has
//! already finished, on a directory this job does not own; see
//! [`copy_verified`] for what lands under the member's name without it.

use super::adopt::md5_of_file;
use crate::par2::Par2Set;
use md5::{Digest, Md5};
use std::io::{Read, Write};
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

/// The file names `out_dir` ALREADY holds that a donation could have
/// written - the same walk [`donor_candidates`] counts, pointed at the
/// job's own directory instead of at a donor.
///
/// The caller's cheap question has two halves and this is the second.
/// "The donors offer nothing" is not "there is nothing to find": a run
/// that donated and then died leaves its placements in `out_dir`, and
/// nothing else records them - a donated file has no journal placements
/// (its articles were never fetched), so the crash-resume path cannot
/// see it and the successor re-downloads a file that is whole and
/// byte-exact on its own disk. Asking THIS directory before paying for
/// the PAR2 index keeps the common case - a fresh switch whose donors
/// have been swept - at exactly the zero cost `donor_candidates` bought.
pub fn placed_names(out_dir: &Path) -> Vec<String> {
    donor_files(out_dir)
        .into_iter()
        .filter_map(|(p, _)| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .collect()
}

/// Copy `src` to `dst`, hashing the bytes as they pass, and answer
/// whether what was copied is `want`.
///
/// # Why the digest is taken HERE and not off the donor beforehand
///
/// The screen in [`donate_whole_files`] proves a file on the donor's
/// disk WAS the member at the moment it was read. The copy is a second
/// read, and a donor is a directory this job does not own: between the
/// two, a retention sweep, a user delete-and-replace or the
/// predecessor's own repair patch can put different bytes at that path.
/// Verify-in-place-then-`std::fs::copy` would place a torn file under
/// the member's name AND strike every one of its articles out of the
/// fetch plan, which is the one mistake this arm has no way back from:
/// the payload is never asked for, so a repair has only the recovery
/// set to rebuild it from - and §282's founding shape is a job whose
/// recovery set is the part that died.
///
/// Hashing the bytes the copy actually moves closes that window at NO
/// extra I/O: the digest sees the same buffer the write does, so the
/// answer is about this copy rather than about a read that has already
/// finished. The donor's own whole-file screen stays where it is - it
/// is what stops a repack-shaped candidate being copied at all, and
/// dropping it would trade a wasted read for a wasted whole-file write.
///
/// It does not claim the DESTINATION media hold those bytes, and it is
/// not the last word that they do: `replay_or_adopt_restored` seeds
/// every placed span as a resume span, so the M15b backfill re-reads
/// and hashes each one against the PAR2 block map, and the settle
/// read-back backs that up. What this adds is the one check none of
/// those can make cheaply - that the bytes leaving the donor were still
/// the member's at the moment they left.
pub(super) fn copy_verified(src: &Path, dst: &Path, want: [u8; 16]) -> std::io::Result<bool> {
    let mut r = std::fs::File::open(src)?;
    let mut w = std::fs::File::create(dst)?;
    let mut hasher = Md5::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        w.write_all(&buf[..n])?;
    }
    Ok(<[u8; 16]>::from(hasher.finalize()) == want)
}

/// Folded member names this set describes more than once with facts
/// that DISAGREE.
///
/// Two FileDesc packets naming one file identify no single member, and
/// the two would land on one path: the first placed wins the name, the
/// second finds a destination that is not itself and is left alone -
/// so the successor's file carries whichever member came first in set
/// order and its articles are struck out either way. That is a coin
/// flip on bytes there is no way back from, and it needs only a
/// malformed set to arrange.
///
/// The same rule [`crate::preflight::probe_recovery_set`] applies to a
/// FileDesc length two members disagree about, one rung wider because
/// this arm turns on more than the length: a name is ambiguous when the
/// members behind it differ in length, first-16k MD5 or whole-file MD5.
/// Two byte-identical descriptions of one file are NOT ambiguous -
/// there is only one answer to give - and refusing those would refuse
/// a duplicated packet, which is a thing real sets carry.
///
/// Folded the way [`donate_whole_files`] names the destination, and
/// then lowercased: on the two case-insensitive filesystems this ships
/// on, `V.bin` and `v.bin` ARE one path, and on the third refusing both
/// costs a donation that would have been legitimate - which is the safe
/// direction, the same one the caller's own duplicate-hint rule takes.
fn ambiguous_names(set: &Par2Set) -> std::collections::HashSet<String> {
    let mut seen: std::collections::HashMap<String, (u64, [u8; 16], [u8; 16])> =
        std::collections::HashMap::new();
    let mut bad = std::collections::HashSet::new();
    for f in &set.files {
        let key = crate::disk::sanitize_filename(&f.name).to_lowercase();
        let facts = (f.length, f.md5_16k, f.md5);
        match seen.get(&key) {
            Some(prev) if *prev != facts => {
                bad.insert(key);
            }
            Some(_) => {}
            None => {
                seen.insert(key, facts);
            }
        }
    }
    bad
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
/// it would have struck out, which is exactly today's behaviour. So
/// does a copy whose own bytes do not add up to the member's MD5 - see
/// [`copy_verified`], which is the rung that judges the COPY rather
/// than the read that chose it.
///
/// # What the caller owes this pass
///
/// It will hash any destination whose length matches a member's, even
/// when the donors offer nothing at all, because that arm is the only
/// thing that can recognise a PREVIOUS pass's own donation. A
/// partially-fetched destination has the right length too and can only
/// ever answer no after a whole-file read, so a caller with a resume on
/// its hands passes the members no article of which has been fetched
/// and keeps the rest out. `get::donor` does exactly that.
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
    // No early return on an empty `cands`, and that is the R6 fix
    // rather than an oversight. "The donors offer nothing" used to end
    // the pass here, which also ended the already-here arm below - the
    // one thing that can recognise a PREVIOUS pass's own donation. A
    // donated file has no journal placements (its articles were never
    // fetched), so nothing else on the resume path can see it, and a
    // crash-resume whose predecessor has since been swept re-downloaded
    // a file sitting whole and verified in its own `out_dir`.
    //
    // What that costs is the caller's to weigh and it is NOT free: the
    // arm's first rung is a metadata call, but a destination whose
    // LENGTH matches goes on to a whole-file MD5, and on this box that
    // is ~440 MB/s wall - about 93 s over a 40 GB post. A
    // partially-fetched member has the right length (the writer
    // preallocates) and usually the right first 16k (the plan fetches
    // each file's offset-0 article first), so it reaches that read and
    // can only ever answer no. `get::donor` therefore hands this pass
    // only the members no article of which has been fetched, which is
    // what a donation looks like and what an in-progress download does
    // not.
    //
    // One MD5 per candidate at most, however many members probe it - a
    // renamed multi-volume set pairs N members with N candidates, and
    // without the caches that is N^2 passes over the payload.
    let mut head_cache: Vec<Option<[u8; 16]>> = vec![None; cands.len()];
    let mut whole_cache: Vec<Option<[u8; 16]>> = vec![None; cands.len()];
    let mut taken = vec![false; cands.len()];
    let ambiguous = ambiguous_names(set);
    for f in &set.files {
        if f.length == 0 {
            continue;
        }
        let name = crate::disk::sanitize_filename(&f.name);
        // Two members disagreeing under one name identify neither: see
        // `ambiguous_names`. Skipped on BOTH arms, so an ambiguous name
        // is neither copied nor reported already-placed - reporting it
        // would strike the articles out just as surely as placing it.
        if ambiguous.contains(&name.to_lowercase()) {
            continue;
        }
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
            // condemn - and hashed AS IT IS COPIED, so what earns the
            // rename is this copy and not the screen above it, which
            // read the donor at an earlier instant. See `copy_verified`.
            let tmp = out_dir.join(format!(".{name}.donating"));
            let _ = std::fs::remove_file(&tmp);
            match copy_verified(p, &tmp, f.md5) {
                Ok(true) => {}
                // The donor changed under us between the screen and the
                // copy. Drop the candidate rather than the member: some
                // other donor may still hold the real thing, and this
                // one has just proved it cannot be trusted twice.
                Ok(false) => {
                    let _ = std::fs::remove_file(&tmp);
                    taken[ci] = true;
                    continue;
                }
                Err(_) => {
                    let _ = std::fs::remove_file(&tmp);
                    break;
                }
            }
            if std::fs::rename(&tmp, &dest).is_err() {
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
