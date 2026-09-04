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
use nzbkit::par2::Par2Set;
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
    nzbkit::disk::sanitize_out_name(name).to_lowercase()
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

/// Which member names this NZB actually posts, folded, to NZB file
/// index - the map every later step in this pass looks a set member up
/// in.
///
/// A free function rather than the inline loop it was until 31 Aug
/// 2026, so that [`bridge_obfuscated_by_length`]'s tests start from the
/// map `adopt_from_donors` really builds. A test helper that MIRRORS a
/// production loop is a test of the mirror: this arm's whole obfuscated
/// defect is a statement about what these keys are, so a copy would
/// have gone on agreeing with itself after the original moved.
fn wanted_names(nzb: &Nzb) -> std::collections::HashMap<String, usize> {
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
    want
}

/// Cut the probed set down to the members this pass may hand to
/// `donate_whole_files`, and leave `want` able to attribute what comes
/// back. Returns how many members the length bridge had to place.
///
/// One function and not three statements at the call site, because the
/// three are one decision and because the middle one is invisible
/// otherwise: a lift whose helper is tested but whose CALL is not is a
/// lift that a later edit can drop in silence, with every test still
/// green. Removing the bridge from this body reddens
/// `an_obfuscated_post_survives_the_narrowing_that_used_to_empty_it`,
/// which was verified by driving exactly that mutation.
fn narrow_to_donatable(
    nzb: &Nzb,
    set: &mut Par2Set,
    want: &mut std::collections::HashMap<String, usize>,
    unfetched: &[bool],
) -> usize {
    // The obfuscated lift, and it goes FIRST because this is where the
    // FileDesc names first exist: `want` is keyed on NZB subjects, the
    // retains below read the set's own names, and on a hash-subject
    // post those two vocabularies never meet. Before the retains, so
    // the set is still the full probed one - the census's gate is about
    // how many members the POST has, not how many survived a filter.
    let bridged = bridge_obfuscated_by_length(nzb, set, want);
    set.files.retain(|f| want.contains_key(&fold(&f.name)));
    // On the donors_offer == 0 path nothing can be COPIED - the donors
    // hold nothing - so every member handed on is a whole-file read
    // looking for a previous donation, and only an unfetched member can
    // be one; this is the half that keeps the R6 widening free (see the
    // gate in the caller for what it costs without it). On the offer > 0
    // path the same retain is what makes `donate_whole_files`' caller
    // contract true: a resumed switch with unswept donors would
    // otherwise hand the already-here arm every partially-fetched
    // member - right length from preallocation, right first 16k from
    // offset-0-first - and buy a whole-file MD5 per member that can
    // only ever answer no, and a member the journal already owns
    // articles of is not a donation target either way.
    set.files
        .retain(|f| want.get(&fold(&f.name)).is_some_and(|&fi| unfetched[fi]));
    bridged
}

/// Extend `want` with the members the NAME bridge could not place, by
/// LENGTH - the lift of this arm's obfuscated limit.
///
/// # What was actually in the way, which is not what the limit said
///
/// `want` is keyed on the NZB SUBJECT's filename hint, and on an
/// obfuscated post that hint is a hash - `nzb::quoted_filename`'s last
/// fallback takes the first non-empty quoted run, dot or no dot - so
/// the map is populated, just under the wrong name. The FileDesc
/// packets carry the REAL names. So the two name bridges either side -
/// `set.files.retain(|f| want.contains_key(..))` and the
/// `want.get(&fold(&d.name))` in the placement loop - both miss, the
/// retain empties the set, and the pass donates nothing.
///
/// The arm's own comment used to call that unfixable "because the
/// pre-fetch has no yEnc `name=` to read", and the handoff that
/// commissioned this lift first repeated it. Both were wrong: this pass
/// FETCHES the recovery index (`probe_par2_sets` below) before either
/// bridge is consulted, so the FileDesc lengths are in hand at exactly
/// the point the names fail. Nothing has to be re-ordered and no extra
/// article is fetched - the lift is this map gaining the entries the
/// subject could not give it. (What order DOES still cost is written up
/// at the `donors_offer == 0` gate below, and is a different, narrower
/// case.)
///
/// # The gate is the set's member COUNT, and it is the only guard here
///
/// [`super::dupefill::donor_file_by_length`] carries the rule and the
/// census behind it: single-member sets only, an encoded/decoded ratio
/// window, and unique-or-refuse. Its single-member gate is what makes
/// this loop run over at most one member and insert at most one entry,
/// so there is deliberately no second "is this NZB file already
/// claimed" check - two guards either of which suffices leaves both
/// unfalsifiable, which is the trap `tools/cfg-safety-gate.py`'s header
/// records and which cost the dupefill lane a surviving mutation.
/// `a_multi_volume_obfuscated_post_bridges_nothing` is the ratchet.
///
/// # What a wrong answer costs HERE, which is not what it costs in
/// `dupefill`
///
/// That module's header says a wrong pairing buys "a wasted fetch and
/// nothing else", because every borrowed block is proved against the
/// target's own MD5 before a byte is written. THAT DOES NOT TRANSFER.
/// This arm STRIKES articles out of the fetch plan, which this module's
/// own opening calls the one mistake it has no way back from - so a
/// wrong `fi` here would place the right bytes under the right name and
/// then never ask for a DIFFERENT file at all.
///
/// What keeps that unreachable is a necessary condition rather than a
/// second guard, and it is worth spelling out because it is not
/// obvious. Striking wrongly needs the NZB to post two or more `Data`
/// files, exactly ONE of them inside the window (or uniqueness refuses),
/// and that one to be the wrong carrier. But the member's TRUE carrier
/// has the member's own length, so it is in the window by definition of
/// the window - which means the wrong one being alone in there requires
/// the true one to be OUTSIDE it, i.e. a client family no census has
/// seen, `[1.0167, 1.0328]` measured against `[1.005, 1.045]` allowed.
/// The digest `donate_whole_files` takes before placing is what makes
/// the bytes right regardless; this is what makes the STRIKE right.
///
/// Returns how many members were bridged, for the caller's log line.
fn bridge_obfuscated_by_length(
    nzb: &Nzb,
    set: &Par2Set,
    want: &mut std::collections::HashMap<String, usize>,
) -> usize {
    let mut bridged = 0usize;
    for f in &set.files {
        let key = fold(&f.name);
        if want.contains_key(&key) {
            continue;
        }
        let Some(fi) = super::dupefill::donor_file_by_length(nzb, set, f.length) else {
            continue;
        };
        want.insert(key, fi);
        bridged += 1;
    }
    bridged
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
    // copy of beside. An obfuscated post - whose subjects are
    // hashes and whose real names live only in the FileDesc packets -
    // maps its files under those HASHES here, so it meets the set's own
    // names nowhere. That used to end the pass, written up as a limit of
    // the pre-fetch; it is not one. `bridge_obfuscated_by_length` lifts
    // it off the recovery index this pass already fetches.
    let mut want = wanted_names(nzb);
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
    // A STATED LIMIT of the obfuscated lift, priced and left unbought.
    //
    // This gate is the ONE place the lift does not reach, and it is
    // reached by ORDER rather than by vocabulary: `want` is hash-keyed
    // and `placed_names` returns the FileDesc names an earlier donation
    // wrote, so on an obfuscated post the two miss here exactly as they
    // miss after the probe - but here there is no probe behind us to
    // read real names out of, and buying one is the whole cost of this
    // pass. So the case this gate cannot see is narrow and specific: an
    // earlier pass of THIS job donated obfuscated members, died, and the
    // donors have been swept since, leaving bytes only `out_dir` knows
    // about (a donated file has no journal placements - its articles
    // were never fetched - so the resume path is blind to it too).
    //
    // What lifting it would cost is what this gate was built to refuse:
    // an index fetch, plus up to `PROBE_BUDGET`, on every donor-bearing
    // job whose donors are swept - which is the COMMON case here, a
    // fresh switch - to salvage a second-order one that is only
    // reachable at all now that the lift above lets an obfuscated
    // donation happen in the first place. The failure mode of not
    // buying it is a re-download this arm has always had, never a wrong
    // byte. Not worth it on today's evidence.
    //
    // The tempting free version - reading the SIZES `donor_files`
    // already returns and asking the ratio question of them - is not
    // built either, and deliberately: the census's rule is single-member
    // ONLY, that gate needs the SET, and the set is what we do not have
    // yet. A size-only arm would be the rule with its one guard removed.
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
    let bridged = narrow_to_donatable(nzb, &mut set, &mut want, &unfetched);
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
            match (regained, bridged) {
                (0, 0) => String::new(),
                (0, _) => format!(", {bridged} named by length off the recovery index"),
                (_, 0) => format!(", {regained} already here from an earlier pass"),
                _ => format!(
                    ", {regained} already here from an earlier pass, \
                     {bridged} named by length off the recovery index"
                ),
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
    use md5::Digest as _;
    use std::collections::HashSet;

    fn nzb(xml: &str) -> Nzb {
        Nzb::parse(xml.as_bytes()).expect("test NZB parses")
    }

    /// A minimal but well-formed PAR2 index: a Main packet listing one
    /// id per member and a FileDesc for each, carrying the two facts
    /// `bridge_obfuscated_by_length` reads - the member's NAME and its
    /// LENGTH. No IFSC and no recovery slices; `Par2Set::parse` leaves
    /// `blocks` empty for a file with no IFSC packet and nothing here
    /// asks about blocks. Same builder as `smart::setclaim`'s, kept
    /// local for the same reason it is: `identity.rs`'s copy is
    /// `#[cfg(feature = "indexer")]` and this must hold on the slim
    /// build too.
    fn par2_set(members: &[(&str, u64)]) -> Par2Set {
        let set = 7u8;
        let pkt = |ptype: &[u8; 16], body: &[u8]| -> Vec<u8> {
            let mut p = Vec::new();
            p.extend_from_slice(nzbkit::par2::MAGIC);
            p.extend_from_slice(&(64 + body.len() as u64).to_le_bytes());
            p.extend_from_slice(&[0u8; 16]);
            p.extend_from_slice(&[set; 16]);
            p.extend_from_slice(ptype);
            p.extend_from_slice(body);
            let md5: [u8; 16] = md5::Md5::digest(&p[32..]).into();
            p[16..32].copy_from_slice(&md5);
            p
        };
        let fid = |i: usize| -> [u8; 16] { [set.wrapping_add(i as u8).wrapping_add(1); 16] };
        let mut main = Vec::new();
        main.extend_from_slice(&4096u64.to_le_bytes());
        main.extend_from_slice(&(members.len() as u32).to_le_bytes());
        for i in 0..members.len() {
            main.extend_from_slice(&fid(i));
        }
        let mut idx = pkt(b"PAR 2.0\0Main\0\0\0\0", &main);
        for (i, (name, len)) in members.iter().enumerate() {
            let mut d = Vec::new();
            d.extend_from_slice(&fid(i));
            d.extend_from_slice(&[set ^ (i as u8) ^ 0x40; 16]);
            d.extend_from_slice(&[set ^ (i as u8) ^ 0x80; 16]);
            d.extend_from_slice(&len.to_le_bytes());
            d.extend_from_slice(name.as_bytes());
            while !d.len().is_multiple_of(4) {
                d.push(0);
            }
            idx.extend(pkt(b"PAR 2.0\0FileDesc", &d));
        }
        Par2Set::parse(&[idx.as_slice()]).expect("the fixture index parses")
    }

    /// One NZB file per (subject, encoded segment sizes). The subject is
    /// what `want` is keyed on, so a HASH here is the whole obfuscated
    /// case; the segment `bytes` are what the ratio is taken over.
    fn posting(files: &[(&str, &[u64])]) -> Nzb {
        let mut x = String::from(
            "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
        );
        for (subject, segs) in files {
            x.push_str(&format!(
                "<file poster=\"a@b\" date=\"1\" subject=\"&quot;{subject}&quot; yEnc (1/{})\">\n\
                 <groups><group>alt.bin</group></groups>\n<segments>\n",
                segs.len()
            ));
            for (i, b) in segs.iter().enumerate() {
                x.push_str(&format!(
                    "<segment bytes=\"{b}\" number=\"{}\">{subject}-{i}@t</segment>\n",
                    i + 1
                ));
            }
            x.push_str("</segments>\n</file>\n");
        }
        x.push_str("</nzb>\n");
        nzb(&x)
    }

    /// A real post's encoded sum over its decoded length, at the census
    /// MEDIAN (1.03232 over 369 wire-probed obfuscated postings). Every
    /// fixture below posts at this ratio rather than at an arbitrary one
    /// inside the window, so no test here can be read as licence to
    /// widen the window to fit it.
    fn encoded_for(len: u64) -> u64 {
        (len as f64 * 1.03232) as u64
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

    /// The premise this whole lift rests on, asserted rather than
    /// assumed, and it is not what the arm's old comment said.
    ///
    /// A hash subject IS a parseable filename hint, so `want` is
    /// POPULATED on an obfuscated post - keyed under the hash. What
    /// fails is not the map being empty, it is the map and the FileDesc
    /// packets speaking two different vocabularies. Anyone who reads
    /// "maps nothing" literally, as the census's own prescription
    /// invites, builds a fallback that never fires.
    ///
    /// The rule it rests on is `nzb::quoted_filename`'s LAST fallback,
    /// "else the first non-empty quoted run" - not `filename_hint`
    /// versus `filename_hint_lenient`, which is the natural guess and is
    /// wrong: a dotless hash needs neither the unquoted parse nor the
    /// dotted-run rule, and swapping the lenient call for the strict one
    /// changes nothing here. Measured by driving both mutations; only
    /// dropping that fallback reddens this.
    #[test]
    fn an_obfuscated_subject_is_a_hint_so_want_is_full_and_still_meets_nothing() {
        const LEN: u64 = 4 << 20;
        let n = posting(&[("a1b2c3d4e5f60718", &[encoded_for(LEN)])]);
        let want = wanted_names(&n);
        assert_eq!(want.len(), 1, "the hash subject parses as a hint");
        assert!(
            want.contains_key(&fold("a1b2c3d4e5f60718")),
            "and the map is keyed under that HASH, not under nothing"
        );
        let set = par2_set(&[("Real.Name.mkv", LEN)]);
        assert!(
            !want.contains_key(&fold(&set.files[0].name)),
            "which is why the retain empties the set: the FileDesc's real \
             name is a key this map does not have"
        );
    }

    /// The lift. One obfuscated payload plus a readable PAR2 - 712 of
    /// the 718 wire-probed obfuscated recovery sets in the census - is
    /// named by the only other thing the NZB states about a file.
    #[test]
    fn an_obfuscated_single_member_post_is_bridged_by_encoded_length() {
        const LEN: u64 = 4 << 20;
        let n = posting(&[("a1b2c3d4e5f60718", &[encoded_for(LEN)])]);
        let set = par2_set(&[("Real.Name.mkv", LEN)]);
        let mut want = wanted_names(&n);
        assert_eq!(bridge_obfuscated_by_length(&n, &set, &mut want), 1);
        assert_eq!(
            want.get(&fold(&set.files[0].name)),
            Some(&0),
            "the member now resolves to the NZB file that carries it"
        );
        // Which is the whole point: both name bridges either side of the
        // probe now answer, so the retain keeps the member and the
        // placement loop can attribute the donation to a file index.
        let mut files = set.files.clone();
        files.retain(|f| want.contains_key(&fold(&f.name)));
        assert_eq!(files.len(), 1, "the retain no longer empties the set");
    }

    /// The lift WIRED IN, which is a different claim from the lift
    /// working: `narrow_to_donatable` is the one place the bridge is
    /// called, and this drives the whole post-probe path an obfuscated
    /// post used to die on.
    ///
    /// It exists because the first cut of these tests called the bridge
    /// directly and NOTHING failed when the call site was reverted -
    /// a helper with tests and a call with none is a lift a later edit
    /// drops in silence. Verified by driving exactly that mutation.
    #[test]
    fn an_obfuscated_post_survives_the_narrowing_that_used_to_empty_it() {
        const LEN: u64 = 4 << 20;
        let n = posting(&[("a1b2c3d4e5f60718", &[encoded_for(LEN)])]);
        let mut want = wanted_names(&n);
        let mut set = par2_set(&[("Real.Name.mkv", LEN)]);
        assert_eq!(
            narrow_to_donatable(&n, &mut set, &mut want, &[true]),
            1,
            "one member named by length off the recovery index"
        );
        assert_eq!(
            set.files.len(),
            1,
            "and the member SURVIVES the retain that used to empty the set - \
             which is the whole defect, and is invisible to a test that calls \
             the bridge itself"
        );
        assert_eq!(
            want.get(&fold("Real.Name.mkv")),
            Some(&0),
            "so the placement loop can attribute the donation to a file index"
        );
    }

    /// A member this job has already fetched an article of is an
    /// in-progress download and not a donation target, and the bridge
    /// must not smuggle one past that rule - the R6 cost model is the
    /// same whichever vocabulary named the member.
    #[test]
    fn a_bridged_member_this_job_is_already_downloading_is_still_dropped() {
        const LEN: u64 = 4 << 20;
        let n = posting(&[("a1b2c3d4e5f60718", &[encoded_for(LEN)])]);
        let mut want = wanted_names(&n);
        let mut set = par2_set(&[("Real.Name.mkv", LEN)]);
        assert_eq!(
            narrow_to_donatable(&n, &mut set, &mut want, &[false]),
            1,
            "the bridge still names it - that is not the question here"
        );
        assert!(
            set.files.is_empty(),
            "and the unfetched retain still drops it, so a partially fetched \
             member never buys a whole-file MD5 that can only answer no"
        );
    }

    /// The measured-dead half, and the ratchet on refusing it: 99.6% of
    /// real multi-volume sets post every body volume at ONE length, so
    /// there is nothing for a length rule to read and the answer is
    /// refusal rather than a nearest match.
    ///
    /// The fixture is deliberately the one multi-volume shape where
    /// length WOULD otherwise work - N-1 equal plus one short, queried
    /// through its short last volume - with a single candidate posted,
    /// so the member count is the only thing that can refuse it. Two
    /// guards either of which sufficed would leave both unfalsifiable,
    /// which is what let a mutation survive in the dupefill lane.
    #[test]
    fn a_multi_volume_obfuscated_post_bridges_nothing() {
        const BODY: u64 = 4 << 20;
        const LAST: u64 = 1 << 20;
        let n = posting(&[("beefcafebeefcafe", &[encoded_for(LAST)])]);
        let multi = par2_set(&[("m.part1.rar", BODY), ("m.part2.rar", LAST)]);
        // The premise, asserted: on a ONE-member set this very candidate
        // at this very length IS bridged, so nothing but the member
        // count separates the two answers.
        let single = par2_set(&[("m.part2.rar", LAST)]);
        let mut w1 = wanted_names(&n);
        assert_eq!(bridge_obfuscated_by_length(&n, &single, &mut w1), 1);
        let mut w2 = wanted_names(&n);
        assert_eq!(
            bridge_obfuscated_by_length(&n, &multi, &mut w2),
            0,
            "and refused outright the moment the post has a second member"
        );
        assert_eq!(w2, wanted_names(&n), "a refusal leaves the map untouched");
    }

    /// A NAMED post must take the name, not the length - the bridge is a
    /// fallback and never a second opinion. Worth its own test because
    /// the two answers differ here: the set's `readme.txt` is the NZB's
    /// file 1, while its ENCODED size would put it against file 0.
    #[test]
    fn a_name_that_already_bridges_is_never_relitigated_by_length() {
        const LEN: u64 = 4 << 20;
        let n = posting(&[("readme.txt", &[encoded_for(LEN)])]);
        let set = par2_set(&[("readme.txt", LEN)]);
        let mut want = wanted_names(&n);
        assert_eq!(
            bridge_obfuscated_by_length(&n, &set, &mut want),
            0,
            "the name bridge answered, so the length one is never asked"
        );
        assert_eq!(want.get(&fold("readme.txt")), Some(&0));
    }

    /// Ambiguity refuses, exactly as two NZB files posting one NAME
    /// refuse in the `want` build above. A wrong pairing here spends a
    /// fetch, so the rule is unique-or-refuse and never nearest-match.
    #[test]
    fn two_nzb_files_of_one_length_bridge_neither() {
        const LEN: u64 = 4 << 20;
        let n = posting(&[
            ("a1b2c3d4e5f60718", &[encoded_for(LEN)]),
            ("f7e6d5c4b3a29180", &[encoded_for(LEN)]),
        ]);
        let set = par2_set(&[("Real.Name.mkv", LEN)]);
        let mut want = wanted_names(&n);
        assert_eq!(bridge_obfuscated_by_length(&n, &set, &mut want), 0);
        assert!(
            !want.contains_key(&fold("Real.Name.mkv")),
            "two candidates in the window identify neither"
        );
    }

    /// The par2-volume decoy the census measured at 7.6% of the
    /// payload's encoded size: outside the window, refused. This is the
    /// arm that keeps the bridge from pairing a member against the
    /// recovery data protecting it.
    #[test]
    fn a_candidate_outside_the_ratio_window_bridges_nothing() {
        const LEN: u64 = 4 << 20;
        let n = posting(&[("a1b2c3d4e5f60718", &[encoded_for(LEN)])]);
        let mut want = wanted_names(&n);
        assert_eq!(
            bridge_obfuscated_by_length(&n, &par2_set(&[("Real.Name.mkv", LEN)]), &mut want),
            1,
            "at its own length the single candidate is the member"
        );
        let mut want = wanted_names(&n);
        assert_eq!(
            bridge_obfuscated_by_length(&n, &par2_set(&[("Real.Name.mkv", LEN / 2)]), &mut want),
            0,
            "and at a length no client family could explain it is refused"
        );
    }

    /// The fixtures above state their encoded sums outright rather than
    /// running an encoder, so this is what stops them drifting into a
    /// shape the population does not have: the ratio they post at must
    /// be the census MEDIAN, not merely somewhere inside the window.
    /// A fixture that only passes on the margin is one drift from
    /// proving nothing, and widening the window to rescue one would be
    /// moving a measured rule to fit a synthetic post.
    #[test]
    fn the_fixtures_post_at_the_censuss_median_ratio() {
        const LEN: u64 = 4 << 20;
        let ratio = encoded_for(LEN) as f64 / LEN as f64;
        assert!(
            (1.0322..=1.0324).contains(&ratio),
            "fixture ratio {ratio:.5} has drifted off the measured median 1.03232"
        );
    }
}
