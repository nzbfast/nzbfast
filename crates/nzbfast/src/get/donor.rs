//! §293 plan-side adoption: strike a member file out of the fetch plan
//! when a failed predecessor already has it, whole and byte-exact.
//!
//! # What §293 shipped, and what it did not
//!
//! §293 threaded `donor_dirs` from the daemon's history through
//! `get::settle` / `get::tail` / `repair` to the disk repair's adoption
//! scan, and that arm is real: a repair that would otherwise report
//! Unrepairable completes, which is what its own A/B measures. But the
//! scan runs AFTER the fetch, so it can never pre-empt a download - and
//! §293's plan had asked for the other thing, in its own words:
//! "Baseline: successor fetches 100% of the post. Treatment: successor
//! fetches only the unadopted remainder."
//!
//! TODO 305 item 2 measured the gap off the mock's own body ledger: a
//! promoted spare whose predecessor left 39 of 40 payload blocks
//! verified on disk fetched **41 bodies for a 40-article payload** - the
//! whole payload plus the PAR2 main index. This module is that item.
//!
//! # Why it needs the successor's own PAR2 set, and fetches it
//!
//! Skipping a file has to be PROVED, because there is no way back: the
//! payload would never be fetched, and a repair cannot rebuild what was
//! never asked for. A repack - same names, same lengths, different bytes
//! - is exactly the shape that would poison it, and the only evidence
//! that separates a repack from the real thing is a digest the
//! SUCCESSOR's set states. An NZB carries none: a filename hint and
//! encoded segment sizes, nothing content-derived.
//!
//! So the pre-pass fetches the successor's PAR2 main index on its own,
//! ahead of the plan, and reads the FileDesc packets out of it. That
//! costs one small article set - the same index the plan fetches again a
//! moment later, because activation needs its packets in memory - and it
//! is the whole extra cost of this arm. It is paid only on a job that
//! HAS donors, which is a spare promotion, a hunt enqueue or a §284
//! parked switch; `donor_dirs` is documented empty on the CLI, the
//! sidecar and every ordinary job, and this returns without touching the
//! disk or the network for those.
//!
//! # Every failure is "no donation", never a failed job
//!
//! No par2 main in the NZB, a probe that answers nothing, a donor
//! directory that cannot be read, a copy that runs out of space, a file
//! whose name the NZB and the set spell differently: each of those
//! leaves the fetch plan exactly as it would have been. The property
//! `a_donor_with_wrong_bytes_donates_nothing_and_changes_nothing` pinned
//! for the repair-time arm is the rule here too, and the bar is one rung
//! stricter - that arm may adopt a BLOCK on a CRC hit confirmed by block
//! MD5, this one places a file only on its whole-file MD5.

use crate::*;
use nzbkit::nzb::FileKind;
use std::path::{Path, PathBuf};
use tracing::info;

/// What the pre-pass hands the plan.
#[derive(Default)]
pub(super) struct Donated {
    /// Indexed by NZB FILE index: this file's bytes are already in
    /// `out_dir`, so none of its articles may be queued.
    pub(super) by_file: Vec<bool>,
    /// `(nzb file index, on-disk name, length)` for the extractor and
    /// verifier seeds - the same three facts a crash resume's `SlotSeed`
    /// carries, and they take the same adopt path.
    pub(super) placed: Vec<(usize, String, u64)>,
    /// Declared bytes of the articles this saves, for the banner.
    pub(super) bytes: u64,
}

impl Donated {
    pub(super) fn any(&self) -> bool {
        !self.placed.is_empty()
    }
}

/// Ceiling on the whole pre-pass, which sits between the job starting
/// and its first payload byte. `probe_par2_sets` already caps itself per
/// server; this caps the sum, so the worst case is a bounded delay
/// rather than three thirty-second timeouts in a row.
const PROBE_BUDGET: std::time::Duration = std::time::Duration::from_secs(45);

/// The set name an NZB file would be posted under, folded the way
/// `census.rs` folds it: the PAR2 FileDesc and the NZB subject are two
/// records of one filename written by different tools.
fn fold(name: &str) -> String {
    nzbkit::disk::sanitize_filename(name).to_lowercase()
}

/// Per NZB file index: has this run's resume journal accounted for NO
/// article of it?
///
/// A file donated by an earlier pass answers yes and always will - its
/// articles were struck out of that pass's plan, so none of them was
/// ever fetched and none of them is in the journal. A file this job has
/// started downloading answers no from its first completed article. The
/// ids are bracketed the way `build_fetch_plan` brackets them, through
/// one reused buffer rather than a `format!` per segment: this walks
/// every article of the post and a 128k-article NZB is not a rare one.
fn unfetched_files(nzb: &Nzb, completed: &std::collections::HashSet<String>) -> Vec<bool> {
    let mut key = String::new();
    nzb.files
        .iter()
        .map(|f| {
            !f.segments.iter().any(|s| {
                key.clear();
                key.push('<');
                key.push_str(&s.message_id);
                key.push('>');
                completed.contains(key.as_str())
            })
        })
        .collect()
}

/// Could `names` - what `out_dir` already holds - be an earlier pass's
/// own donation, rather than this run's half-finished download?
///
/// Cheap on purpose: a readdir and a hash lookup, asked BEFORE the PAR2
/// index is fetched, so a fresh switch whose donors have been swept
/// still costs exactly nothing. A `true` here buys the index fetch and
/// a whole-file read of the untouched members, and nothing more.
fn a_donation_may_already_be_here(
    names: &[String],
    want: &std::collections::HashMap<String, usize>,
    unfetched: &[bool],
) -> bool {
    names.iter().any(|n| {
        want.get(&fold(n))
            .is_some_and(|&fi| unfetched.get(fi).copied().unwrap_or(false))
    })
}

pub(super) async fn adopt_from_donors(
    servers: &[nzbkit::config::ServerConfig],
    nzb: &Nzb,
    out_dir: &Path,
    donors: &[PathBuf],
    completed: &std::collections::HashSet<String>,
) -> Donated {
    let mut out = Donated {
        by_file: vec![false; nzb.files.len()],
        ..Default::default()
    };
    if donors.is_empty() || servers.is_empty() {
        return out;
    }
    // The index, not a recovery volume: only the main index is
    // guaranteed to carry the FileDesc packets for every member, and a
    // volume's recovery slices would be megabytes of nothing this pass
    // reads.
    let Some(main) = nzb.files.iter().find(|f| f.kind() == FileKind::Par2Main) else {
        return out;
    };
    let ids: Vec<String> = main
        .segments
        .iter()
        .map(|s| format!("<{}>", s.message_id))
        .collect();
    if ids.is_empty() {
        return out;
    }
    // Ask the cheap question first. Fetching the index is this pass's
    // entire cost, and a donor directory that offers no file at all -
    // already swept, or unreadable - can never repay it. The second
    // half of the question is asked below, once `want` is built: a
    // donor with nothing to give is not the same as nothing to find.
    let donors_offer = nzbkit::par2repair::donor_candidates(donors, out_dir);
    // Which member names this NZB actually posts, so a member the plan
    // could not strike out is never copied: bytes in `out_dir` under a
    // name no slot writes are bytes the fetch would then write a second
    // copy of beside. An obfuscated post - whose subjects are hashes and
    // whose real names live only in the FileDesc packets - maps nothing
    // here and donates nothing, which is a stated limit of this arm
    // rather than a bug: the pre-fetch has no yEnc `name=` to read.
    let mut want: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (fi, f) in nzb.files.iter().enumerate() {
        if f.kind() != FileKind::Data || f.segments.is_empty() {
            continue;
        }
        if let Some(hint) = f.filename_hint_lenient() {
            // A repeated name identifies no single file, so NEITHER
            // claim is trusted - the same rule `probe_recovery_set`
            // applies to a FileDesc length two members disagree about.
            // Donating to the first would put the bytes at a name the
            // second file's writer then has to be disambiguated away
            // from, which is worse than fetching both.
            match want.entry(fold(hint)) {
                std::collections::hash_map::Entry::Occupied(mut o) => {
                    o.insert(usize::MAX);
                }
                std::collections::hash_map::Entry::Vacant(v) => {
                    v.insert(fi);
                }
            }
        }
    }
    want.retain(|_, fi| *fi != usize::MAX);
    if want.is_empty() {
        return out;
    }
    // Sweep finding R6. `donors_offer == 0` used to end the pass here,
    // and it ended one thing too many: a run that donated and then died
    // leaves its placements in THIS job's `out_dir`, and nothing else
    // can see them. A donated file has no journal placements - its
    // articles were never fetched - so the crash-resume path is blind
    // to it, and a successor whose predecessor has since been swept
    // re-downloaded a file whole and byte-exact on its own disk.
    //
    // The cost of looking is real and is why the gate is two-sided
    // rather than simply deleted. `donate_whole_files` reads a
    // destination whole once its LENGTH matches, and a
    // partially-fetched member has the right length (the writer
    // preallocates) and usually the right first 16k (the plan fetches
    // each file's offset-0 article first) - so it would reach that read
    // and could only ever answer no. Measured on the dev Mac, MD5 is
    // ~440 MB/s wall: a 40 GB post is ~93 s of stall before the first
    // byte is asked for, on every resumed switch, to salvage a donation
    // that usually is not there.
    //
    // So two questions, both free. Does `out_dir` hold a name this NZB
    // posts at all (one readdir), and is that file one this job has
    // fetched NO article of? A donation is exactly the second shape - a
    // file present with nothing in the journal behind it - and an
    // in-progress download is exactly not. What is left to hash is a
    // handful of untouched members, whose 16k head is unwritten and
    // rejects after 16 KB unless the file really was donated.
    // Computed on BOTH paths: the cheap out_dir gate below is the
    // donors_offer == 0 half, and the retain after the probe needs the
    // answer whichever way the offer went. On a fresh job `completed`
    // is empty and every entry is true, so nothing narrows.
    let unfetched = unfetched_files(nzb, completed);
    if donors_offer == 0
        && !a_donation_may_already_be_here(
            &nzbkit::par2repair::placed_names(out_dir),
            &want,
            &unfetched,
        )
    {
        return out;
    }
    // The probe bounds itself per server (three servers, thirty seconds
    // each), and this bounds the sum: a switch job whose index is
    // unfetchable everywhere must not hold its own download at the
    // starting line for a minute and a half to learn that. It will fetch
    // the index again in the plan and fail there on its own terms.
    let t0 = std::time::Instant::now();
    let probe = nzbkit::preflight::probe_par2_sets(servers, &ids);
    // The LARGEST set only, and that is a decision rather than an
    // oversight (TODO 311's last box, item B's shape). The probe adopts
    // every set its accumulated articles cover; `donate_whole_files`
    // takes exactly one `Par2Set`, and its `ambiguous_names` rail - the
    // thing that
    // stops a name two members disagree about being donated to
    // either - is scoped to that one set. Handing it each set in turn would run
    // that rail per set, so two sets naming one file with different
    // digests would each look unambiguous and the first would place its
    // bytes: "a coin flip on bytes there is no way back from", which is
    // the exact sentence the rail was written under. Widening it means
    // the rail seeing the union, which is a change to `par2repair` with
    // its own tests.
    //
    // Conservative in the safe direction, and strictly better than what
    // it replaces: a member outside the largest set is FETCHED rather
    // than donated, which is what happened to every member of every set
    // before this - the old singular door answered `None` the moment the
    // articles covered two sets and this pass donated nothing at all.
    let probed = tokio::time::timeout(PROBE_BUDGET, probe).await;
    let Ok(Some(mut set)) = probed.map(|o| o.and_then(|sets| sets.into_iter().next())) else {
        info!(
            target: "repair",
            "donor adoption: the recovery set's index did not come back in {:.2?} - \
             fetching the post in full",
            t0.elapsed()
        );
        return out;
    };
    set.files.retain(|f| want.contains_key(&fold(&f.name)));
    // On the donors_offer == 0 path nothing can be COPIED - the donors
    // hold nothing - so every member handed on is a whole-file read
    // looking for a previous donation, and only an unfetched member can
    // be one; this is the half that keeps the R6 widening free (see the
    // gate above for what it costs without it). On the offer > 0 path
    // the same retain is what makes `donate_whole_files`' caller
    // contract true: a resumed switch with unswept donors would
    // otherwise hand the already-here arm every partially-fetched
    // member - right length from preallocation, right first 16k from
    // offset-0-first - and buy a whole-file MD5 per member that can
    // only ever answer no, and a member the journal already owns
    // articles of is not a donation target either way.
    set.files
        .retain(|f| want.get(&fold(&f.name)).is_some_and(|&fi| unfetched[fi]));
    if set.files.is_empty() {
        return out;
    }
    let placed = nzbkit::par2repair::donate_whole_files(&set, donors, out_dir);
    // Copied off a donor, or recognised where an earlier pass of THIS
    // job left it: the plan strikes the articles either way, and the
    // log has to say which, because they are two different facts about
    // where the run stands. `from` is the destination itself on the
    // second, which is what tells them apart.
    let mut regained = 0usize;
    for d in placed {
        let Some(&fi) = want.get(&fold(&d.name)) else {
            continue;
        };
        if out.by_file[fi] {
            continue;
        }
        if d.from.parent() == Some(out_dir) {
            regained += 1;
        }
        out.by_file[fi] = true;
        out.bytes = out
            .bytes
            .saturating_add(nzb.files[fi].segments.iter().map(|s| s.bytes).sum::<u64>());
        out.placed.push((fi, d.name, d.length));
    }
    if out.any() {
        info!(
            target: "repair",
            "donor adoption: {} whole file(s) taken off the predecessor's disk{} in {:.2?} - \
             {:.1} MB of this post will not be fetched",
            out.placed.len() - regained,
            if regained > 0 {
                format!(", {regained} already here from an earlier pass")
            } else {
                String::new()
            },
            t0.elapsed(),
            out.bytes as f64 / 1e6,
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn nzb(xml: &str) -> Nzb {
        Nzb::parse(xml.as_bytes()).expect("test NZB parses")
    }

    fn two_file_nzb() -> Nzb {
        nzb(r#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file subject='"m.part1.rar" yEnc (1/2)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="100" number="1">a1@t</segment><segment bytes="100" number="2">a2@t</segment></segments>
 </file>
 <file subject='"m.part2.rar" yEnc (1/1)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="100" number="1">b1@t</segment></segments>
 </file>
</nzb>"#)
    }

    /// The R6 discriminator: a file this job has fetched NO article of
    /// is what a previous pass's donation looks like, and a file with
    /// even one completed article is what an in-progress download looks
    /// like. Getting this backwards is not a correctness bug, it is the
    /// whole cost model - a partially fetched member has the right
    /// length and usually the right first 16k, so admitting it buys a
    /// whole-file MD5 that can only ever answer no.
    #[test]
    fn a_file_with_one_completed_article_is_a_download_and_not_a_donation() {
        let n = two_file_nzb();
        assert_eq!(
            unfetched_files(&n, &HashSet::new()),
            [true, true],
            "with an empty resume set nothing has been fetched"
        );
        let one: HashSet<String> = ["<a2@t>".to_string()].into_iter().collect();
        assert_eq!(
            unfetched_files(&n, &one),
            [false, true],
            "ONE completed article is enough to say this file is being \
             downloaded, not donated"
        );
        let both: HashSet<String> = ["<a1@t>".to_string(), "<b1@t>".to_string()]
            .into_iter()
            .collect();
        assert_eq!(unfetched_files(&n, &both), [false, false]);
        // The ids are bracketed the way `build_fetch_plan` brackets
        // them; a bare message-id must match nothing, or the whole
        // discriminator inverts.
        let bare: HashSet<String> = ["a1@t".to_string()].into_iter().collect();
        assert_eq!(unfetched_files(&n, &bare), [true, true]);
    }

    /// The cheap half of the R6 gate, asked BEFORE the PAR2 index is
    /// fetched: a fresh switch whose donors have been swept must still
    /// cost exactly nothing, and a resumed one that may be sitting on
    /// its own earlier donation must pay for a look.
    #[test]
    fn out_dir_is_only_worth_probing_for_a_name_this_post_has_not_fetched() {
        let mut want = std::collections::HashMap::new();
        want.insert(fold("m.part1.rar"), 0usize);
        want.insert(fold("m.part2.rar"), 1usize);

        assert!(
            !a_donation_may_already_be_here(&[], &want, &[true, true]),
            "an empty out_dir - the fresh switch - buys nothing"
        );
        assert!(
            !a_donation_may_already_be_here(
                &["something-else.bin".to_string()],
                &want,
                &[true, true]
            ),
            "a name this post does not post cannot be its donation"
        );
        assert!(
            !a_donation_may_already_be_here(&["m.part1.rar".to_string()], &want, &[false, true]),
            "a member this job has started downloading is not a donation"
        );
        assert!(
            a_donation_may_already_be_here(&["m.part1.rar".to_string()], &want, &[true, false]),
            "a member present with nothing in the journal behind it IS \
             the shape a donation leaves"
        );
        // Folded the way the set names the destination: the on-disk
        // name is the SET's, sanitized, and the two spellings of one
        // filename must still meet.
        assert!(
            a_donation_may_already_be_here(&["M.PART2.RAR".to_string()], &want, &[false, true]),
            "case must not lose the match - the FileDesc and the NZB \
             subject are two records of one filename"
        );
    }
}
