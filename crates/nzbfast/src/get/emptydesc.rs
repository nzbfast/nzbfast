//! Zero-length FileDescs - the VIDEO_TS placeholder shape of the no-RAR
//! deobfuscation family: `VTS_02_0.VOB`, 0 bytes, its real name nowhere
//! but the PAR2 FileDesc.
//!
//! Every content tier requires bytes, and rightly so: the live matcher's
//! md5-16k fallback hashes a head that does not exist for an empty file
//! (`nzbkit::live` `try_match`), adoption wants `len > 0` on both sides
//! (`nzbkit::par2repair::adopt`), and none of those gates may loosen - an
//! empty read has no head to hash, and loosening them is how a wrong
//! match happens. But a zero-length descriptor also contributes ZERO
//! damage (`length.div_ceil(block_size) == 0`), so on an otherwise clean
//! download repair never runs, the needs-resize rebuild that CAN
//! materialize the file is never reached, and the job finishes "clean"
//! with a "file missing entirely" warning about a file that costs nothing
//! to produce. The placeholder keeps its random name forever.
//!
//! What rescues the case is that a zero-length FileDesc is identified by
//! name and length alone, and its content claim is FIXED: the MD5 of the
//! empty input is a constant, so a descriptor declaring length 0 with
//! that MD5 is proven against any empty file by construction. Creating an
//! empty file IS the whole-file-MD5 proof the repair path would have run.
//! Two rules keep it sound:
//!
//! * A descriptor whose declared MD5 is NOT the empty digest is
//!   malformed (no zero-length file can hash to anything else) and is
//!   left alone.
//! * Nothing here may take a name from, or truncate, a non-empty file.
//!   The pairing tier only renames an on-disk file a fresh `stat` proves
//!   empty, and the materialize tier declines when anything already sits
//!   at the target name.
//!
//! Two zero-length descriptors are interchangeable in content, so name
//! assignment among them is arbitrary but DETERMINISTIC: descriptors in
//! missing-list order (which is set order, FileDesc order within a set),
//! empty slot files in slot order, paired first to first. Descriptors
//! past the last empty slot are materialized outright.

use crate::*;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use tracing::{info, warn};

/// MD5 of the empty input (`d41d8cd98f00b204e9800998ecf8427e`) - the one
/// whole-file digest a zero-length FileDesc can honestly declare.
const EMPTY_MD5: [u8; 16] = [
    0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e,
];

/// Land every zero-length FileDesc still on the missing list, either by
/// renaming a proven-empty unclaimed slot file onto it or by
/// materializing the empty file outright. Landed names are removed from
/// `missing_files`, so the damage loop neither warns "missing entirely"
/// about them nor offers them to a repair that has nothing to rebuild.
///
/// Runs on the settle path BEFORE the repair decision, so it covers the
/// rename-only shape (undamaged set, no repair run) that the
/// needs-resize rebuild in `nzbkit::par2repair` can never reach - and
/// when repair does run, the file is already in place and verifies
/// intact rather than being rebuilt beside a leftover junk copy.
#[expect(clippy::too_many_arguments)]
pub(super) fn land_zero_length_filedescs(
    missing_files: &mut Vec<String>,
    sets: &[Arc<nzbkit::par2::Par2Set>],
    set_has_claims: &[bool],
    offered_names: &HashSet<String>,
    slots: &[Arc<FileSlot>],
    slot_file: &[usize],
    nzb: &Nzb,
    reports: &[(usize, nzbkit::live::SlotReport)],
    extractor: &nzbkit::extract::Extractor,
    out_dir: &Path,
    published_names: &mut crate::unpack::PublishedNames,
) {
    // Zero-length descriptors still unlanded. First set naming a file
    // owns it, and a stray set's descriptors are skipped - the ownership
    // rule is the damage loop's, and the stray rule IS the damage
    // loop's, called rather than copied
    // ([`super::residual::is_a_stray_release`]), so this tier cannot
    // produce a file that loop would refuse to charge.
    let adopt: Vec<&nzbkit::par2::Par2File> = missing_files
        .iter()
        .filter_map(|name| {
            let f = sets
                .iter()
                .find_map(|set| set.files.iter().find(|f| f.name == *name))?;
            if f.length != 0 {
                return None;
            }
            if super::residual::is_a_stray_release(sets, set_has_claims, offered_names, f) {
                return None;
            }
            if f.md5 != EMPTY_MD5 {
                warn!(
                    target: "verify",
                    "{} declares length 0 with a non-empty MD5 - malformed descriptor, left alone",
                    f.name
                );
                return None;
            }
            Some(f)
        })
        .collect();
    if adopt.is_empty() {
        return;
    }

    // On-disk files eligible to take a name: settled slots no set
    // claimed, fully arrived (a slot that lost articles could hold a
    // 0-byte file for the wrong reason), not archive-mapped or chased
    // (no finished file), whose file a fresh stat PROVES empty. The
    // posted-bytes belt is the same idea as the spare-pairing sanity
    // band: a zero-length post is nothing but yEnc framing, so a slot
    // whose NZB declares real payload never pairs however clean its
    // counters read.
    let covered: HashSet<usize> = reports.iter().map(|(s, _)| *s).collect();
    let empty_slots: Vec<(usize, PathBuf)> = slots
        .iter()
        .enumerate()
        .filter(|(i, s)| {
            !s.is_par2()
                && !s.sample_skipped
                && !covered.contains(i)
                && s.missing.load(Ordering::Relaxed) == 0
                && s.remaining.load(Ordering::Relaxed) == 0
                && s.errors.load(Ordering::Relaxed) == 0
                && s.abandoned.load(Ordering::Relaxed) == 0
                && !extractor.is_mapped(*i)
                && !extractor.is_chased(*i)
                && nzb.files[slot_file[*i]].bytes() <= 4096
        })
        .filter_map(|(i, _)| {
            let p = extractor.slot_path(i)?;
            std::fs::metadata(&p)
                .is_ok_and(|m| m.len() == 0)
                .then_some((i, p))
        })
        .collect();

    let mut landed: HashSet<String> = HashSet::new();
    let mut empty_slots = empty_slots.into_iter();
    for f in adopt {
        if let Some((sidx, path)) = empty_slots.next() {
            // GH #63's rule, same as the non-empty settle rename: a slot
            // whose posted name beats the descriptor's keeps it.
            if super::settle::filedesc_name_is_better(&slots[sidx], &f.name) {
                if let Some(new) =
                    publish_verified_name(&path, &f.name, out_dir, sidx, published_names)
                {
                    extractor.note_slot_renamed(sidx, new);
                }
                info!(
                    target: "verify",
                    "✔ {} - zero-length in the set, satisfied by the empty file posted as {}",
                    f.name, slots[sidx].hint
                );
                landed.insert(f.name.clone());
            } else {
                // X6-03: the gate REFUSES here - the slot's own posted
                // name is the truthful one and keeps it - but that only
                // proves the descriptor's CONTENT claim, not its OUTPUT.
                // On the disc-placeholder shape this tier exists for, the
                // structure file a player opens is the descriptor's OWN
                // path, and content interchangeability between two empty
                // files does not put anything there. So the descriptor's
                // own name still has to be materialized, right beside the
                // slot's kept file - both are empty, so there is nothing
                // to duplicate and nothing to disambiguate.
                if materialize_empty_filedesc(f, out_dir) {
                    landed.insert(f.name.clone());
                }
            }
        } else {
            // The shared member-name function: a zero-length FileDesc can
            // spell a tree path too (a VIDEO_TS placeholder), and it must
            // materialize where the rest of the set lands.
            if materialize_empty_filedesc(f, out_dir) {
                landed.insert(f.name.clone());
            }
        }
    }
    missing_files.retain(|n| !landed.contains(n));
}

/// Materialize an empty file at a zero-length descriptor's own sanitized
/// path, or confirm one is already there. Returns whether the descriptor
/// is satisfied.
///
/// Two callers: past the last paired empty slot, and X6-03's refused-gate
/// arm, where a slot keeps its own better name and the descriptor's OWN
/// path still needs a file under it. Both are the same question - is
/// there a real empty file at the descriptor's exact path - so one
/// function answers it once.
///
/// NOT routed through [`crate::unpack::PublishedNames::claim`]:
/// disambiguating a contested name there means a `{slot:03}-` prefix that
/// moves a whole subtree (see that type's own doc), which would
/// materialize the file at the WRONG path for a structural placeholder -
/// the one thing this tier must never do. A materialize is instead
/// all-or-nothing at the descriptor's own exact path: either an empty
/// file lands there, or nothing does and the descriptor stays owed, which
/// the finish-time re-read ([`unsatisfied_at_finish`]) then catches.
fn materialize_empty_filedesc(f: &nzbkit::par2::Par2File, out_dir: &Path) -> bool {
    let real = nzbkit::disk::sanitize_out_name(&f.name);
    // Made INSIDE the directory the walk validated, anchored on the
    // output root: `open_out_leaf_under` creates what the name needs and
    // opens the leaf in the last of those directories, so no component
    // below `out_dir` is re-resolved between the check and the create.
    // `CreateNew` is the mode this arm has always needed - a zero-length
    // descriptor must never truncate a file already at the name - and it
    // is what the `AlreadyExists` arm below reads.
    let target = nzbkit::disk::join_out_name(out_dir, &real);
    match nzbkit::disk::open_out_leaf_under(out_dir, &real, nzbkit::disk::LeafOpen::CreateNew) {
        Ok(_) => {
            info!(
                target: "verify",
                "✔ {real} - zero-length in the set, materialized (the MD5 of an \
                 empty file is the descriptor's own)"
            );
            true
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // X6-04: `symlink_metadata`, never `metadata` - a symlink at
            // the target pointing at any empty file OUTSIDE the job would
            // otherwise answer `len() == 0` too, and the descriptor would
            // be marked landed with nothing ever written inside the job
            // directory. Grade by inode, not by path: `is_file()` refuses
            // the link (and a FIFO or device, which `metadata` would also
            // have opened and could block a settle pass on).
            if std::fs::symlink_metadata(&target).is_ok_and(|m| m.is_file() && m.len() == 0) {
                true
            } else {
                warn!(
                    target: "verify",
                    "{real} already exists and is not an empty regular file - left \
                     alone (a zero-length descriptor must never truncate a file or \
                     adopt a link)"
                );
                false
            }
        }
        Err(e) => {
            warn!(target: "verify", "could not materialize {real}: {e}");
            false
        }
    }
}

/// Fail the verdict for every zero-length member this job owed and,
/// after every landing tier and every repair has run, still has not
/// delivered - naming each one. Returns whether it found any.
///
/// # Why the verdict needs this at all
///
/// Wave-4 rows W4-09 and M4-45, both measured red on origin/main on
/// 30 Aug 2026. A zero-length FileDesc prices at
/// `0.div_ceil(block_size)` = ZERO blocks of damage, so it is the one
/// member whose absence no other accounting can see: no repair is asked
/// for it, `damage == 0` reads as "the recovery set found nothing
/// wrong", and neither `incomplete` nor the decode/write error count
/// knows it exists - there is no SLOT behind a descriptor nobody
/// posted. W4-09 is what that looks like from the log: `already exists
/// and is not empty - left alone`, then `✘ VIDEO_TS/VTS_02_0.VOB - file
/// missing entirely`, then `clean download ✔`, and rc=0. Every tier
/// above behaved correctly and the job still lied about the result.
///
/// # Why it is a re-read of the directory and not a flag
///
/// The charge loop runs BEFORE `run_set_repair`, and a repair over a
/// set that took damage from some OTHER file can materialize a
/// zero-length member on its way past (the needs-resize rebuild in
/// `nzbkit::par2repair`). Deciding at charge time would fail a job that
/// went on to deliver the file. The directory at the end is the only
/// answer that is true of the run that actually happened, and it costs
/// one `metadata` call per unpriced name - a list that is empty on
/// every ordinary job.
///
/// # What counts as delivered
///
/// The descriptor's whole claim, and nothing weaker. A zero-length
/// FileDesc declares two things: a path, and a content digest. So a
/// file must EXIST at the descriptor's own sanitized output path AND be
/// empty - which is what makes W4-09's occupant not an answer: real
/// bytes at that path are somebody else's file, not this member. And a
/// descriptor declaring a whole-file digest other than the empty one is
/// unsatisfiable BY CONSTRUCTION - the MD5 of a zero-length file is a
/// constant, so no file of any kind can ever meet that claim - and is
/// reported without looking at the disk at all (row M4-45).
///
/// Nothing here writes, renames or truncates anything: the materialize
/// question - when a zero-length descriptor may put a file somewhere -
/// is settled one tier up in [`land_zero_length_filedescs`], and this
/// pass deliberately stays on the accounting side of that line.
///
/// The verdict LINE lives here rather than at the one call site because
/// `settle_with_set` sat at 500 of the size gate's 500-line ceiling on
/// 30 Aug 2026 - exactly on it even after this lift - and because the
/// sentence only makes sense beside the argument above it.
pub(super) fn report_unsatisfied_zero_length(
    unpriced: &[super::residual::Unpriced],
    sets: &[Arc<nzbkit::par2::Par2Set>],
    out_dir: &Path,
) -> bool {
    let absent = unsatisfied_at_finish(unpriced, sets, out_dir);
    for name in &absent {
        warn!(
            target: "verify",
            "✘ {name} - declared in the recovery set and never delivered; it is \
             zero-length, so no amount of parity prices or repairs it - this is \
             not a clean download"
        );
    }
    !absent.is_empty()
}

/// The undelivered names themselves - split from the reporting above so
/// the decision can be unit-tested without a log to read.
fn unsatisfied_at_finish(
    unpriced: &[super::residual::Unpriced],
    sets: &[Arc<nzbkit::par2::Par2Set>],
    out_dir: &Path,
) -> Vec<String> {
    unpriced
        .iter()
        .filter(|u| {
            let Some(f) = sets
                .get(u.set)
                .and_then(|s| s.files.iter().find(|f| f.name == u.name))
            else {
                // The descriptor the charge loop just read cannot have
                // gone; if it somehow has, say so rather than passing.
                return true;
            };
            if f.md5 != EMPTY_MD5 {
                return true;
            }
            let real = nzbkit::disk::sanitize_out_name(&f.name);
            // X6-04's rule applies here too: this is the LAST line of
            // defense for "is this descriptor really delivered", so a
            // symlink to an external empty file must not read as
            // satisfied any more than the materialize tier may create
            // one. `symlink_metadata` plus `is_file()` grades the inode
            // actually sitting in the job directory, not whatever a link
            // resolves to.
            !std::fs::symlink_metadata(nzbkit::disk::join_out_name(out_dir, &real))
                .is_ok_and(|m| m.is_file() && m.len() == 0)
        })
        .map(|u| u.name.clone())
        .collect()
}

/// A PRODUCT RULING, 30 Aug 2026 (Wave-4 adversarial row W4-14): at most
/// this many aliases per `(MD5, length)` group are materialized from one
/// posted copy.
///
/// A RULING AND NOT A MEASUREMENT. Nothing here has been benched, and
/// the number is not a description of any real release - MultiPar's
/// dedupe posts run to a handful. It exists to bound what a KILOBYTE OF
/// DESCRIPTOR can command: the fan-out is metadata-driven, so without a
/// cap a small packet file buys arbitrarily many whole-file writes, and
/// that is the whole of the W4-14 hazard. Moving it is a product
/// decision, not a tuning one.
const DUPLICATE_FANOUT_CAP: usize = 32;

/// Finding F10 (capability corpus, 30 Aug 2026): a DEDUPE POST - two
/// FileDescs declaring identical (MD5, length), one posted copy. The
/// arrived copy claims one descriptor; the other counted as "missing
/// entirely", and the identical verified bytes sitting right there
/// could never help - adoption excludes identified targets by design,
/// so at realistic redundancy the job died on a post that carried
/// every byte it needed. MultiPar emits this shape on purpose: a
/// kilobyte of descriptor buys a whole duplicate file.
///
/// The rescue is the zero-length tier's argument one step up: the
/// descriptor's content claim is fully checkable RIGHT HERE. Read the
/// sibling's on-disk file, hash it, and if the whole-file MD5 is the
/// missing descriptor's own, a byte copy IS the whole-file-MD5 proof
/// the repair path would have run. The hash is computed fresh from the
/// bytes being copied - never trusted from the sibling's claim - so a
/// damaged sibling can never seed a silent duplicate.
///
/// The sibling's file is found through a descriptor-to-CURRENT-path
/// ledger built from `reports`, and NOT by rebuilding
/// `out_dir/<descriptor name>` - which is the point (W4-18, 30 Aug
/// 2026). A verified member does not always sit at its own name: a
/// collision policy one pass earlier may have given it a `{slot:03}-`
/// spelling, and the file then at the canonical path is somebody
/// else's. Hashing THAT is how the rescue rejected a perfectly good
/// sibling and left the duplicate to a repair it did not need. Any pass
/// that runs after publication owes the same rule - guess where an
/// earlier policy put a file and you are hashing whatever it displaced.
///
/// WAVE-4 ROW W4-14 - the same lever pointed the other way. Every part
/// of the rescue above scales with the DESCRIPTOR COUNT, which is what
/// the poster controls: at two aliases it is a kilobyte buying a file,
/// and at two thousand it is a kilobyte buying two thousand full-file
/// reads and two thousand full-file writes. Three bounds, all of them
/// ruled together on 30 Aug 2026:
///
/// * ONE HASH PER GROUP. The content claim is a property of the
///   `(MD5, length)` pair, so proving it once proves it for every
///   descriptor that declares it. The read amplification was pure waste
///   - this is a bound with no behaviour behind it.
/// * CLONE, DON'T COPY. [`nzbkit::disk::copy_file_cow`] takes a
///   filesystem-level reflink where the volume has one, so N aliases of
///   a 40 GB file cost one file's blocks on APFS and on a reflink-capable
///   Linux volume. Best effort by construction: elsewhere it is the
///   plain copy it always was, which is why the count cap below is the
///   bound that actually holds everywhere.
/// * CAP THE FAN-OUT at [`DUPLICATE_FANOUT_CAP`], and past it REFUSE
///   HONESTLY. The refused names stay on the missing list, so the damage
///   loop below warns about them and the job reports them - the one
///   thing that must not happen is silently truncating a fan-out while
///   telling the user every descriptor was satisfied. The stated trade:
///   a genuine dedupe post naming more than the cap now fails where it
///   used to succeed. That is the ruling. Suspicious metadata fails
///   cleanly rather than being obeyed.
pub(super) fn land_duplicate_filedescs(
    missing_files: &mut Vec<String>,
    sets: &[Arc<nzbkit::par2::Par2Set>],
    set_has_claims: &[bool],
    offered_names: &HashSet<String>,
    reports: &[(usize, nzbkit::live::SlotReport)],
    extractor: &nzbkit::extract::Extractor,
    out_dir: &Path,
) {
    // Where each verified descriptor's file ACTUALLY is, now that the
    // publish pass has run - see the note above.
    let landed_at: HashMap<&str, std::path::PathBuf> = reports
        .iter()
        .filter_map(|(sidx, r)| Some((r.par2_name.as_deref()?, extractor.slot_path(*sidx)?)))
        .collect();
    // Group the still-missing descriptors by the content they CLAIM,
    // built in missing-list order (set order, FileDesc order within a
    // set - the zero-length tier's rule, and the same one the damage
    // loop reads). Both the single hash and the cap are per group, and
    // the order is what makes the cap's survivors deterministic rather
    // than whichever descriptor a hash map happened to yield first.
    // Indexed as well as ordered: the group count is what the POSTER
    // chooses, so a linear scan per descriptor would answer a quadratic
    // CPU cost with another one, in the very function W4-14 is about.
    let mut groups: Vec<((u64, [u8; 16]), Vec<&nzbkit::par2::Par2File>)> = Vec::new();
    let mut index: HashMap<(u64, [u8; 16]), usize> = HashMap::new();
    for name in missing_files.iter() {
        // The damage loop's ownership rule, and the damage loop's own
        // stray guard - called, not copied.
        let Some(f) = sets
            .iter()
            .find_map(|set| set.files.iter().find(|f| f.name == *name))
        else {
            continue;
        };
        if f.length == 0
            || super::residual::is_a_stray_release(sets, set_has_claims, offered_names, f)
        {
            continue;
        }
        let key = (f.length, f.md5);
        match index.get(&key) {
            Some(&i) => groups[i].1.push(f),
            None => {
                index.insert(key, groups.len());
                groups.push((key, vec![f]));
            }
        }
    }
    let mut landed: HashSet<String> = HashSet::new();
    for (_, members) in &groups {
        land_duplicate_group(
            members,
            sets,
            missing_files,
            &landed_at,
            out_dir,
            &mut landed,
        );
    }
    missing_files.retain(|n| !landed.contains(n));
}

/// Materialize one `(MD5, length)` group from the single on-disk sibling
/// that already carries the content: resolve the sibling once, clone it
/// into a PRIVATE temp, prove that temp once, then clone the proven temp
/// per alias up to [`DUPLICATE_FANOUT_CAP`].
///
/// The sibling is group-invariant and that is not an assumption: every
/// member's own name IS on the missing list and the sibling's is not, so
/// the `g.name != f.name` clause the per-alias search used to carry is
/// satisfied by construction for every member at once.
///
/// WAVE-5 ROW X5-07 - WHY THE PROOF AND THE BYTES MUST NAME ONE INODE.
/// This function used to prove the SOURCE by path, test the destination
/// with `target.exists()`, and then hand both paths to
/// [`nzbkit::disk::copy_file_cow`]. Two independent defects, measured
/// red on 30 Aug 2026 by
/// `a_dangling_alias_at_the_duplicate_name_is_replaced_and_never_followed`
/// in `crates/nzbfast/tests/e2e_emptydesc/mod.rs`:
///
/// * THE DESTINATION WAS NOT BOUND. `Path::exists` FOLLOWS symlinks, so
///   a DANGLING link planted at the duplicate's canonical name answered
///   false, `copy_file_cow`'s clone arm refused an existing destination,
///   and the plain-copy fallback followed the link and created the file
///   it pointed at. 180 KB landed OUTSIDE the job's output directory and
///   the job returned rc=0, logging "whole-file MD5 verified on the
///   bytes copied" over a file it had never read. Silent, outside, and
///   reported as success - the worst combination available.
/// * PROOF-THEN-REOPEN. The digest was taken on a handle that was then
///   DROPPED, and the copy re-resolved the source BY PATH. Bytes swapped
///   between the two were copied unproved under a log line claiming they
///   were verified.
///
/// The shape that fixes both at once, and the reason it is one mechanism
/// rather than two patches: every byte this function lands is a clone of
/// ONE inode that it proved, reached only through a name nothing outside
/// this call can predict, and the descriptor's own - post-derivable -
/// name is touched by `rename` alone, which follows nothing and replaces
/// whatever sits there atomically.
///
/// * THE PROOF IS OF THE COPY, NOT OF THE SOURCE. The sibling is cloned
///   into `.nzbfast-dup-<pid>-<nanos>-<n>.tmp` under `out_dir` and THAT
///   is what gets hashed. A source swapped at any point after the clone
///   cannot reach the temp, and a source swapped before it produces a
///   temp that fails the digest and refuses the whole group. One hash
///   per group, exactly as W4-14 ruled - the read moved, it did not
///   multiply.
/// * THE TEMP NAME IS NOT DERIVABLE FROM THE POST. The adversary here is
///   a hostile NZB/PAR2, which chooses DESCRIPTOR names and so can plant
///   anything it likes at `out_dir/<descriptor name>` before the job
///   starts. It cannot plant at a name built from this process's pid and
///   a nanosecond clock, which is what makes a private temp the right
///   staging ground and `target` the wrong one.
/// * NOTHING IS EVER WRITTEN THROUGH THE PUBLIC NAME. `rename` replaces
///   a dangling symlink with a regular file rather than following it, so
///   the planted-alias arm lands `Copy.Two.bin` as a real in-output inode
///   instead of writing through the link - which is what the row asks
///   for, and is NOT the same as refusing when anything exists at the
///   target: a previous run's copy at that name is the ORDINARY case and
///   the duplicate still has to land.
/// * THE FINAL NAME NEVER SEES A PARTIAL FILE. Each alias is cloned to
///   its own temp, fsynced, and only then renamed into place, so a
///   failure at any point leaves the temp (removed here) and never a
///   half-written file under the descriptor's name.
///
/// THE STATED TRADE, which is a cost and not an oversight: staging the
/// proof costs ONE extra clone per group. On APFS and on a
/// reflink-capable Linux volume that is metadata and no bytes, which is
/// the case W4-14's clone arm exists for; everywhere else it is one
/// extra full-file copy against the group's `made` copies, bounded by
/// [`DUPLICATE_FANOUT_CAP`]. Consuming the proof temp as the last
/// alias's file would recover it and was rejected: the proof would then
/// have to be cloned from a PUBLIC name for every alias but one, which
/// is the binding this row exists to establish, sold back for 3% of a
/// bounded copy count.
fn land_duplicate_group(
    members: &[&nzbkit::par2::Par2File],
    sets: &[Arc<nzbkit::par2::Par2Set>],
    missing_files: &[String],
    landed_at: &HashMap<&str, std::path::PathBuf>,
    out_dir: &Path,
    landed: &mut HashSet<String>,
) {
    let Some(first) = members.first() else { return };
    // A sibling descriptor with the same content claim, anywhere in the
    // active sets, whose own name is not also missing.
    let sibling = sets.iter().flat_map(|s| s.files.iter()).find(|g| {
        g.length == first.length && g.md5 == first.md5 && !missing_files.contains(&g.name)
    });
    let Some(g) = sibling else { return };
    let src = landed_at.get(g.name.as_str()).cloned().unwrap_or_else(|| {
        nzbkit::disk::join_out_name(out_dir, &nzbkit::disk::sanitize_out_name(&g.name))
    });
    // `symlink_metadata` and not `metadata`: a REGULAR file of the right
    // length, never a link to one and never a FIFO or a device, which
    // would otherwise be opened below and can block a settle pass
    // forever. Nothing this pipeline writes puts a link here, so
    // refusing one costs no real post anything.
    if !std::fs::symlink_metadata(&src).is_ok_and(|m| m.is_file() && m.len() == first.length) {
        return;
    }
    // Stage the group's ONE proven inode under a name the post cannot
    // name. Everything below clones from this and nothing re-reads
    // `src`.
    let proof = dedupe_temp_path(out_dir, 0);
    if let Err(e) = nzbkit::disk::copy_file_cow(&src, &proof) {
        warn!(target: "verify", "could not stage {}'s content for its duplicate(s): {e}", g.name);
        let _ = std::fs::remove_file(&proof);
        return;
    }
    let digest = whole_file_md5(&proof);
    info!(
        target: "verify",
        "duplicate-descriptor group: {} missing alias(es) of {}, source hashed once",
        members.len(), g.name
    );
    // `None` is a read error on our own staged copy, which proves the
    // content no better than a mismatch does - both leave the aliases
    // to repair rather than landing bytes nothing vouched for.
    if digest != Some(first.md5) {
        warn!(
            target: "verify",
            "{} share {}'s declared content but the bytes on disk do not hash to it - \
             leaving the duplicate(s) to repair",
            members.len(), g.name
        );
        let _ = std::fs::remove_file(&proof);
        return;
    }
    let mut made = 0usize;
    let mut refused = 0usize;
    for (i, f) in members.iter().enumerate() {
        if made >= DUPLICATE_FANOUT_CAP {
            refused += 1;
            continue;
        }
        let real = nzbkit::disk::sanitize_out_name(&f.name);
        let target = match nzbkit::disk::prepare_out_path(out_dir, &real) {
            Ok(t) => t,
            Err(e) => {
                warn!(target: "verify", "could not place duplicate {real}: {e}");
                continue;
            }
        };
        // The one case where landing would destroy what it is copying.
        // Cannot arise from the group construction (the member's name is
        // missing and the sibling's is not), but two names can sanitize
        // onto one path, and the content is identical either way.
        if target == src || target == proof {
            continue;
        }
        match land_one_alias(&proof, &real, first.length, i + 1, out_dir) {
            Ok(()) => {}
            Err(e) => {
                warn!(target: "verify", "could not write duplicate {real}: {e}");
                continue;
            }
        }
        info!(
            target: "verify",
            "✔ {real} - duplicate descriptor satisfied by copying {} (whole-file MD5 \
             verified on the staged bytes every alias is cloned from)",
            g.name
        );
        landed.insert(f.name.clone());
        made += 1;
    }
    let _ = std::fs::remove_file(&proof);
    if refused > 0 {
        warn!(
            target: "verify",
            "{} descriptors declare {}'s content: materialized {}, refusing the \
             remaining {} - a packet file that commands unbounded duplication is not \
             metadata to obey, and the refused names stay on the missing list rather \
             than being reported satisfied",
            members.len(), g.name, made, refused
        );
    }
}

/// Clone the group's proven inode onto one alias: private temp, fsync,
/// atomic rename. `target` is only ever reached by the rename, so a
/// symlink, a stale file or nothing at all under the descriptor's name
/// all end the same way - a regular in-output inode carrying the proven
/// bytes - and no failure here can leave a partial file under that name.
///
/// X5-06/08/19 OWED ITEM 4 (31 Aug 2026): the temp used to be guarded
/// here, by hand. X5-07 found `copy_file_cow`'s plain-copy fallback
/// following a symlink at its destination and answered it AT THIS CALL
/// SITE - `symlink_metadata` after the fact, plus the temp-then-rename
/// below - while `relpath::open_out_leaf` already spelled the same rule
/// as a mechanism, and two spellings of one rule is how the next one
/// gets written wrong. The alias half now lives in
/// [`nzbkit::disk::copy_file_cow`], which binds its destination on
/// every arm; what stays here is the questions that are about CONTENT
/// rather than about identity - is this the declared length, and is it
/// durable before it is visible.
fn land_one_alias(
    proof: &Path,
    out_name: &str,
    length: u64,
    seq: usize,
    out_dir: &Path,
) -> std::io::Result<()> {
    let tmp = dedupe_temp_path(out_dir, seq);
    let res = (|| -> std::io::Result<()> {
        nzbkit::disk::copy_file_cow(proof, &tmp)?;
        // ONE handle answers both remaining questions. `Existing` is
        // the no-follow reopen that never creates, so a temp that has
        // gone is `NotFound` here rather than an empty file published
        // under the descriptor's name - and `metadata` on the open
        // handle is an fstat, which describes the inode we are about to
        // fsync and rename rather than whatever the name resolves to a
        // moment later.
        let f = nzbkit::disk::open_out_leaf(&tmp, nzbkit::disk::LeafOpen::Existing)?;
        let m = f.metadata()?;
        if !m.is_file() || m.len() != length {
            return Err(std::io::Error::other(format!(
                "staged duplicate at {} is not a regular file of {length} bytes",
                tmp.display()
            )));
        }
        // Durable before it is visible: a rename that beats its own data
        // to the platter publishes the descriptor's name over garbage.
        f.sync_all()?;
        // Bound on the destination side: the directories `out_name`
        // needs are walked from `out_dir` with no component below it
        // re-resolved, so a directory swapped for a link after the
        // target path was computed cannot carry this alias out of the
        // job directory. See `nzbkit::disk::rename_out_under`.
        nzbkit::disk::rename_out_under(out_dir, out_name, &tmp).map(|_| ())
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

/// A staging name under `out_dir` that a hostile packet file cannot
/// predict, and so cannot pre-plant a symlink at. Descriptor names are
/// the post's to choose; this process's pid and the clock are not.
fn dedupe_temp_path(out_dir: &Path, seq: usize) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    out_dir.join(format!(
        ".nzbfast-dup-{}-{nanos:09}-{seq}.tmp",
        std::process::id()
    ))
}

/// Whole-file MD5, read in 1 MiB chunks - a dedupe pair is routinely a
/// whole video file. `None` on any read error, which the caller reads as
/// "cannot prove this content" and leaves the duplicate to repair.
fn whole_file_md5(path: &Path) -> Option<[u8; 16]> {
    use md5::Digest as _;
    use std::io::Read as _;
    let mut fh = std::fs::File::open(path).ok()?;
    let mut h = md5::Md5::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        match fh.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => h.update(&buf[..n]),
            Err(_) => return None,
        }
    }
    Some(h.finalize().into())
}

/// Which adopted sets name a file THIS POST OFFERS, indexed the way
/// `verifier.sets()` is.
///
/// The stray-release guard in [`settle_with_set`] reads a set with no
/// claims and a claimed sibling as a different release's, and that is
/// right for a `.par2` the poster left in the NZB. It is wrong for the
/// MIXTURE - a per-file-set post where ONE file's every article was
/// taken down. From the packets the two are identical (no slot claimed
/// a file of mine, and a sibling set has claims), so the discriminator
/// has to come from outside them, and the NZB is what carries it: a
/// file the post OFFERED and never delivered is not a file the post
/// never mentioned.
///
/// Per FILE, not per set. This answered per SET for a day (any one
/// offered file marked the whole set offered) and that reading hands a
/// STRAY a way past the guard: scene and disc releases share generic
/// names (`01.rar`), so one name collision between a stray's set and a
/// file this post really offers marked the stray's ENTIRE contents as
/// this post's, and its never-posted files were then charged to damage
/// - the exact failure the guard exists to prevent, reintroduced by the
/// census that widened it. Per file, the mixture case still works (the
/// offered-and-lost file is itself the name being tested), and a
/// stray's other files go back to being skipped, collision or not. The
/// trade, stated: a mixture set naming a file the poster omitted from
/// the NZB entirely is no longer charged - and that file is one the
/// post never offered, which is the guard's own definition of not this
/// post's business.
///
/// Matched on the sanitized lowercase name, the same key
/// [`union_set_names`] and the coverage census either side of the guard
/// already use.
///
/// MEASURED 29 Aug 2026 on the three-track rig, one set per track, with
/// track 3's every payload article answered 430 and its own recovery
/// data untouched in the NZB. At 100% redundancy the guard alone exits
/// 1 with `track03.bin` at 0 bytes of 400000 and the log saying it is
/// `a different release's set` - about the post's OWN track; with this
/// census it is rebuilt byte-exact and the job passes. At the ordinary
/// 20% the file is unrepairable either way and what changes is only the
/// sentence: `2000 blocks needed, only 400 recovery blocks in the NZB`
/// instead of a wrong diagnosis.
///
/// STATED LIMIT, and it is why this is ADDITIVE rather than a rewrite of
/// the guard: an OBFUSCATED post names nothing usefully, so a
/// hash-subject slot answers `false` here and its set is skipped exactly
/// as before. Size-banding an unclaimed slot against a FileDesc length -
/// the trick [`reconcile_obfuscated_aliases`] uses for the same "which
/// file was this really" question - was considered and left out on
/// purpose. There the descriptor being paired against is one a repair
/// has already PROVED, and the pairing only ever SPARES a slot; here
/// there is nothing proving it and the answer CHARGES a whole set's
/// content to damage, so a coincidence of size would send a repair
/// shopping for a stray release's parity - the exact failure the guard
/// exists to prevent, reintroduced by the fix for it.
pub(super) fn names_offered_by_the_post(
    slots: &[Arc<FileSlot>],
) -> std::collections::HashSet<String> {
    slots
        .iter()
        .map(|s| nzbkit::disk::sanitize_out_name(&s.hint).to_lowercase())
        .collect()
}

/// The finish-time re-read that decides W4-09 and M4-45, driven
/// directly. The e2e pins in `tests/e2e_emptydesc` cover the whole road
/// to it; these cover the four answers it can give, and the two that
/// must be NO are what stop the fix failing a job that delivered.
#[cfg(test)]
mod unsatisfied_tests {
    use super::*;
    use crate::get::residual::Unpriced;

    fn set_with(name: &str, md5: [u8; 16]) -> Vec<Arc<nzbkit::par2::Par2Set>> {
        vec![Arc::new(nzbkit::par2::Par2Set {
            recovery_set_id: [7u8; 16],
            block_size: 1000,
            files: vec![nzbkit::par2::Par2File {
                file_id: [1u8; 16],
                name: name.to_string(),
                length: 0,
                md5,
                md5_16k: EMPTY_MD5,
                blocks: Vec::new(),
            }],
            nonrecovery: Vec::new(),
            recovery_blocks_seen: 0,
        })]
    }

    /// The in-crate idiom (`tempfile` is not a dependency of this
    /// crate's unit tests): `std::env::temp_dir()` plus a per-TEST name,
    /// and per-test matters - these run concurrently in one binary.
    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new(name: &str) -> TmpDir {
            let d = std::env::temp_dir()
                .join(format!("nzbfast-emptydesc-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).expect("scratch dir");
            TmpDir(d)
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn owed(name: &str) -> Vec<Unpriced> {
        vec![Unpriced {
            set: 0,
            name: name.to_string(),
        }]
    }

    #[test]
    fn an_empty_file_at_the_members_own_path_is_delivered() {
        let d = TmpDir::new("delivered");
        std::fs::create_dir_all(d.0.join("VIDEO_TS")).unwrap();
        std::fs::write(d.0.join("VIDEO_TS/VTS_02_0.VOB"), b"").unwrap();
        assert!(
            unsatisfied_at_finish(
                &owed("VIDEO_TS/VTS_02_0.VOB"),
                &set_with("VIDEO_TS/VTS_02_0.VOB", EMPTY_MD5),
                &d.0,
            )
            .is_empty(),
            "a repair or a landing tier that DID produce the file must not fail the job"
        );
    }

    #[test]
    fn nothing_at_the_path_is_not_delivered() {
        let d = TmpDir::new("absent");
        assert_eq!(
            unsatisfied_at_finish(
                &owed("VTS_02_0.VOB"),
                &set_with("VTS_02_0.VOB", EMPTY_MD5),
                &d.0,
            ),
            vec!["VTS_02_0.VOB".to_string()]
        );
    }

    /// W4-09: real bytes at that path are somebody else's file. The
    /// occupant is left alone one tier up and the member is still owed.
    #[test]
    fn a_nonempty_occupant_does_not_satisfy_the_member() {
        let d = TmpDir::new("occupant");
        std::fs::write(d.0.join("VTS_02_0.VOB"), b"not this member").unwrap();
        assert_eq!(
            unsatisfied_at_finish(
                &owed("VTS_02_0.VOB"),
                &set_with("VTS_02_0.VOB", EMPTY_MD5),
                &d.0,
            ),
            vec!["VTS_02_0.VOB".to_string()]
        );
    }

    /// M4-45: unsatisfiable by construction, so the disk is not even
    /// consulted - an empty file at the path is still not this digest.
    #[test]
    fn a_digest_no_empty_file_can_meet_is_never_delivered() {
        let d = TmpDir::new("lying");
        std::fs::write(d.0.join("VTS_03_0.VOB"), b"").unwrap();
        assert_eq!(
            unsatisfied_at_finish(
                &owed("VTS_03_0.VOB"),
                &set_with("VTS_03_0.VOB", [0x5au8; 16]),
                &d.0,
            ),
            vec!["VTS_03_0.VOB".to_string()]
        );
    }
}
