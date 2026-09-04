//! L1 (31 Aug 2026): a PAYLOAD posted under a recovery VOLUME's name.
//!
//! The volume-spelled half of M4-28, and the one no rescue in
//! `get/settle.rs` can reach BY CONSTRUCTION. `build_fetch_plan`
//! `continue`s on a non-bootstrap [`FileKind::Par2Volume`] BEFORE a slot
//! is built, so such a file has no `sidx`, no `slot_path`, no capture
//! and nothing on disk - and every rescue over there is slot-indexed
//! (`slots[sidx]`, `slot_file[sidx]`, `sniff.matched_deferred`,
//! `extractor.slot_path(sidx)`). It is a gap in their VOCABULARY, not in
//! their evidence, which is why M4-28's `reclaim_par2_named_payload`
//! could not simply be widened onto it.
//!
//! MEASURED end to end on origin/main `632096f71`, 31 Aug 2026, with the
//! `a_par2_subject_over_movie_bytes_is_published_as_payload` fixture and
//! ONE string changed (`abc123.par2` -> `abc123.vol000+50.par2`):
//!
//! ```text
//! [get] ...: 1 files (0.0 MB eager of 2.1 MB total)
//! [get] all 0 files complete ✔
//! [verify] ✘ Vol.Subject.mkv - file missing entirely
//! [repair] unrepairable: 1974 blocks needed, only 395 recovery blocks in the NZB
//! Error: verification failed and PAR2 repair could not complete
//! ```
//!
//! Total loss of a download whose every byte was on the wire, and the
//! job ERRORS rather than finishing green - M4-28's harm profile
//! exactly, and a volume name is if anything the EASIER spelling for a
//! poster to reach for.
//!
//! # WHEN, which is the whole question
//!
//! This is a SCHEDULING problem and not a classification one, and the
//! trap is written up at length in that lane's P1: do NOT reach for it
//! by giving every `Par2Volume` a slot. That skip is what keeps a 10%
//! recovery set on a 50 GB release off the eager path, and the census,
//! the deferral counters and the completion-bar denominator would all
//! have to learn about a slot that exists and is never queued.
//!
//! So the trigger is the moment [`super::shortfall_is_final`] is about
//! to return true - after the donor, adoption, in-set-harvest and
//! repeated-block arms have all declined - with a FileDesc WHOLLY ABSENT
//! from `out_dir`. That is the only instant at which the alternative to
//! spending the fetch is losing the file: on a healthy post every
//! FileDesc is claimed, and on a damaged one that parity can still close
//! the repair never reaches here at all. TESTED rather than trusted -
//! `a_healthy_post_never_spends_the_volume_payload_rescue` is the
//! control arm.
//!
//! # The screen, and why the cost is bounded
//!
//! A payload wearing a volume name is posted like any other file, so its
//! declared WIRE size is its yEnc-encoded length: strictly larger than
//! the FileDesc's declared length and, in practice, a few percent
//! larger. That is a necessary condition, free to check from the NZB
//! alone, and it is what stops this buying every declared volume on a
//! post the arithmetic has already given up on. On the measured fixture
//! it admits exactly the phantom (155,281 bytes against a 150,000-byte
//! FileDesc) and none of the nine real volumes (41,540 through 350,106).
//!
//! On top of the band there is a BYTE BUDGET, and it is the honest
//! statement of what this may cost: **never more wire than the payload
//! it is trying to rescue is worth**, i.e. the total declared length of
//! the absent files plus the same yEnc headroom. Candidates are taken
//! cheapest-first until it is spent.
//!
//! # The proof, and what happens after
//!
//! Landing the bytes is not enough - they have to be IDENTIFIED, and by
//! content rather than by the name the poster gave. Same evidence as
//! M4-28 and as `SniffCtl::matched_deferred`, deliberately: the
//! FileDesc's md5-16k over the first 16 KiB plus an EXACT length match.
//! Nothing here matches by length alone and nothing guesses, so a
//! genuine recovery volume that happened to fall in the band is simply a
//! recovery volume that is now on disk - which the repair below is glad
//! of - and never a file this renames.
//!
//! On a positive match the caller does NOT return: it falls through to
//! [`super::adoption_narrowed_need`], whose native probe re-reads the
//! set OFF DISK. A set the rescue completed comes back `NoDamage` ->
//! `NativeVerdict::Done` -> `NarrowedNeed::Repaired`, and a set it only
//! partly closed comes back with a correctly SMALLER `needed`, which
//! either buys the remaining parity or reports an honest shortfall. No
//! new verdict path had to be invented for either.
//!
//! # Stated limits
//!
//! * The fetch writes under the article's own yEnc `name=`, through the
//!   same `fetch_volume_articles` writer every recovery-volume
//!   side-fetch has always used, so a candidate whose yEnc name collides
//!   with a file already in `out_dir` overwrites it. That exposure is
//!   the side-fetch's and predates this; what is new is one more file in
//!   the fetch. The rename this module performs has no such window: it
//!   only ever targets a name the screen proved ABSENT, re-checked
//!   immediately before the rename.
//! * A candidate that proves to be neither the payload nor usable parity
//!   is LEFT on disk rather than unlinked. Deleting bytes on a job that
//!   is already failing is the wrong direction. It is REPORTED, though,
//!   through `left_behind` - and that half was missing until 31 Aug
//!   2026, when this bullet said the quarantine already owned such a
//!   file and it did not. `get/tail/disposition.rs`'s
//!   `quarantine_failed_payload` covers the `extracted` list and
//!   `held_downloaded_files(slots, ..)`, and a candidate this pass
//!   fetched is in NEITHER: it has no slot (that is the whole reason
//!   this module exists) and it was never extracted. Observed end state
//!   of a failing decline case at `b30f29813`
//!   (`research/MEASUREMENTS-BATCH-2026-08-31.md` section 2):
//!
//!   ```text
//!   testset.par2.nzbfast-partial   39892 bytes   <- quarantine took this
//!   testset.vol007+008.par2       160408 bytes   <- the candidate, BARE
//!   ```
//!
//!   The inversion of the quarantine's own invariant: on a failed job
//!   the one file that arrived through this side door was the only one
//!   left wearing an importable name, and the yEnc name is unconstrained
//!   in general - a candidate posted as `xyz.mkv` leaves a bare
//!   `xyz.mkv` of parity-or-junk bytes. The report is by PATH and not by
//!   name because these files are at the name the POSTER chose, which is
//!   nothing the set can look up.
//!
//!   SCOPED TO A FAILING JOB, because the quarantine is: a COMPLETED job
//!   never runs it, so a leftover would stay bare there. That is not a
//!   hole left open, it is a state the arithmetic cannot reach and the
//!   measurement above PROBED it. `payload_shaped_volumes` caps the buy
//!   at `encoded_upper(absent_total)` and every in-band candidate is by
//!   construction the size of an absent file, so the budget funds about
//!   one candidate per absent file: a DECLINED buy means some absent
//!   FileDesc stayed missing, the set stays unrepairable, and the job
//!   fails. A declined-and-fetched candidate beside a Completed job
//!   needs the budget arithmetic to change first, and whoever changes it
//!   owes this question a second look.
//! * WHAT [`identify`] PROVES IS IDENTITY, NOT WHOLENESS, and the
//!   difference decides what happens to a file this DOES publish when
//!   the job goes on to fail. An exact length plus md5-16k says "these
//!   bytes are that FileDesc"; it says nothing about the 16 KiB-th byte
//!   onward, and this pass ignores `fetch_volume_articles`' failure
//!   count on purpose (see the note at that call). So a candidate that
//!   lost ONE middle article is published under a real payload name with
//!   a zero-filled hole in it: measured 31 Aug 2026, a 150,000-byte
//!   FileDesc rescued with article 3 refused lands 150,000 bytes with
//!   40,452 of them zero, and `left_behind` cannot carry it because the
//!   file was PROVED and renamed rather than left.
//!   THAT IS DELIBERATELY NOT FIXED HERE, and the reason is a REGRESSION
//!   rather than an oversight: the caller gives up outright when this
//!   returns empty, so declining to name a holed candidate would skip
//!   [`super::adoption_narrowed_need`] entirely and throw away the good
//!   blocks the file does carry - on the same fixture, 723 of them,
//!   which on a parity-richer post is the difference between a repair
//!   that closes the hole in place and a job that fails. Identity is
//!   what the repair needs; wholeness is what the DISPOSITION needs, and
//!   it is asked once, later, at the only moment both answers exist:
//!   `get/settle/repair.rs`'s `unproven_rescues`, after that set's
//!   repair has had its turn. It feeds the SAME `left_behind` vector, so
//!   there is still one quarantine door and one log line. See its doc
//!   for the ruling and the two control measurements.
//! * The screen requires the FileDesc to be wholly ABSENT. A payload
//!   posted as a volume is always that shape (nothing else supplies
//!   those bytes), and the strictness is what bounds the spend.
//! * IT IS PER SET, because [`super::fetch_and_repair`] is, so a
//!   multi-set post whose sets have each lost a member can probe the
//!   same candidate once per set. The BOUND still holds - each set
//!   spends at most what its own absent files are worth, and the sum
//!   over sets is the post's own lost payload - but the wire is spent
//!   twice on a shared candidate. Closing it needs cross-set state this
//!   frame does not have, and the shape that would pay for it (many
//!   wholly-lost members across many sets) is a job that has lost
//!   nearly everything anyway.

use super::*;

/// yEnc never shrinks, so the encoded size of a posted file is at least
/// its length; in practice it is a few percent over (escaping, the
/// per-line CR/LF, and the per-article header and trailer the NZB counts
/// in `bytes=`). 1/8 is comfortably above anything a real post produces
/// and is still tight enough to exclude the recovery volumes measured
/// beside the fixture's phantom.
fn encoded_upper(length: u64) -> u64 {
    length.saturating_add(length / 8).saturating_add(16 * 1024)
}

/// The declared `bytes=` of an NZB file is the POSTER's arithmetic, so
/// the floor is the raw length less a small allowance rather than the
/// length itself: a poster who under-declares by a hair must not cost a
/// rescue, and a poster who under-declares by more is outside anything
/// this can reason about.
fn encoded_lower(length: u64) -> u64 {
    length.saturating_sub(length / 64)
}

/// The set's files that are WHOLLY ABSENT from `out_dir` - nothing at
/// the name the set declares. Damaged and short files are deliberately
/// NOT here: they have bytes, so the repair engines above already have
/// something to work with, and admitting them would widen the spend
/// without widening the rescue.
fn absent_files<'s>(
    out_dir: &Path,
    set: &'s nzbkit::par2::Par2Set,
) -> Vec<&'s nzbkit::par2::Par2File> {
    set.files
        .iter()
        .filter(|f| f.length > 0)
        .filter(|f| {
            let p = nzbkit::disk::join_out_name(out_dir, &nzbkit::disk::sanitize_out_name(&f.name));
            !p.exists()
        })
        .collect()
}

/// NZB file indexes of skipped recovery volumes whose declared wire size
/// could be one of `absent`'s files, cheapest first and capped at the
/// byte budget the module header states.
///
/// `already_fetched` is honoured for the same reason `recovery_candidates`
/// honours it: those bytes are on disk, so buying them again is pure
/// wire. The elected BOOTSTRAP volume is covered by that list on every
/// path that has one, and where it is not, its own offset-0 `PAR2\0PKT`
/// election is proof it is parity rather than payload.
fn payload_shaped_volumes(
    nzb: &Nzb,
    already_fetched: &[usize],
    absent: &[&nzbkit::par2::Par2File],
) -> Vec<usize> {
    if absent.is_empty() {
        return Vec::new();
    }
    let mut cand: Vec<(u64, usize)> = Vec::new();
    for (fi, f) in nzb.files.iter().enumerate() {
        if f.kind() != FileKind::Par2Volume || already_fetched.contains(&fi) {
            continue;
        }
        let b = f.bytes();
        if b == 0 {
            continue;
        }
        if absent
            .iter()
            .any(|d| b >= encoded_lower(d.length) && b <= encoded_upper(d.length))
        {
            cand.push((b, fi));
        }
    }
    // Cheapest first, so the budget below buys as many probes as it can
    // rather than one large one. Tie-broken on the file index, so the
    // selection is a function of the NZB and not of iteration order.
    cand.sort_unstable();
    let absent_total = absent.iter().fold(0u64, |a, d| a.saturating_add(d.length));
    let budget = encoded_upper(absent_total);
    let mut spent = 0u64;
    let mut out = Vec::new();
    for (b, fi) in cand {
        let next = spent.saturating_add(b);
        if next > budget {
            continue;
        }
        spent = next;
        out.push(fi);
    }
    out
}

/// Does `path` hold the bytes one of `absent`'s FileDescs describes?
///
/// The M4-28 evidence verbatim - an EXACT length match plus the
/// FileDesc's md5-16k over the first 16 KiB - which is what keeps this
/// conservative in the direction that matters. A truncated or damaged
/// candidate, or a genuine volume for this or any other set, matches
/// nothing and is left exactly where the fetch put it.
fn identify<'s>(
    path: &Path,
    absent: &[&'s nzbkit::par2::Par2File],
) -> Option<&'s nzbkit::par2::Par2File> {
    let len = std::fs::metadata(path).ok().map(|m| m.len())?;
    // 16384 spelled out, as `reclaim_par2_named_payload` does for the
    // named twin: `HASH16K_LEN` is `pub(crate)` to nzbkit.
    let want = usize::try_from(len.min(16384)).ok()?;
    if want == 0 {
        return None;
    }
    let mut head = vec![0u8; want];
    std::fs::File::open(path)
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut head))
        .ok()?;
    let h = nzbkit::par2::md5_16k_of_head(&head, len)?;
    absent
        .iter()
        .copied()
        .find(|d| d.length == len && d.md5_16k == h)
}

/// Put `p` under the name the recovery set gives it, if the bytes prove
/// to be a file the set names and is missing.
///
/// `true` means the bytes are now AT that name and `rescued` names it;
/// `false` means they are still at the yEnc name the fetch chose -
/// declined by the content proof, or proved and not publishable - which
/// is the whole of what the caller reports through `left_behind`. The
/// two are complements BY CONSTRUCTION rather than by a second list
/// somebody has to keep in step: every way out of this function is one
/// of the two answers, so a decline path added below cannot quietly
/// leave a file nobody reports.
fn publish_if_payload(
    p: &Path,
    absent: &[&nzbkit::par2::Par2File],
    out_dir: &Path,
    rescued: &mut Vec<String>,
) -> bool {
    let Some(desc) = identify(p, absent) else {
        return false;
    };
    if rescued.contains(&desc.name) {
        return false;
    }
    let out_name = nzbkit::disk::sanitize_out_name(&desc.name);
    let want = nzbkit::disk::join_out_name(out_dir, &out_name);
    if p != want {
        // Re-checked here and not only at the screen: the screen ran
        // before the fetch, and the fetch writes under yEnc names it
        // does not choose. W4-03's rule is that nothing renames over
        // a file this job already landed.
        if want.exists() {
            warn!(
                target: "par2",
                "{} holds the bytes the recovery set names {} - but something \
                 already occupies that name, so it is left where it is",
                p.display(),
                desc.name
            );
            return false;
        }
        if let Err(e) = nzbkit::disk::create_out_dirs(out_dir, &out_name) {
            warn!(target: "par2", "could not create the path for {}: {e}", desc.name);
            return false;
        }
        if let Err(e) = std::fs::rename(p, &want) {
            warn!(
                target: "par2",
                "could not publish {} as {}: {e}",
                p.display(),
                desc.name
            );
            return false;
        }
    }
    info!(
        target: "par2",
        "a file the NZB named like a recovery volume is payload the recovery \
         set covers ({}) - published as payload rather than left unfetched",
        desc.name
    );
    rescued.push(desc.name.clone());
    true
}

/// Buy the skipped volumes that could BE a file this set declares and is
/// missing, and put whatever proves to be payload under the name the set
/// gives it. Returns the names rescued, empty when nothing was.
///
/// Those names are ALSO the disposition's only handle on the files this
/// PUBLISHES, which `left_behind` deliberately does not carry: nothing
/// else in the job knows they exist, since a published file wears a
/// FileDesc name for a file that by construction has no slot and came
/// out of no archive. The caller hands them to `unproven_rescues`; see
/// the identity-versus-wholeness bullet in the module header.
///
/// `left_behind` is APPENDED with every candidate this pass fetched and
/// did not publish - the bytes are kept where the fetch put them, and
/// the failing job's quarantine renames them aside so nothing imports
/// them (see the module header's stated limit and
/// `get/tail/disposition.rs`). It accumulates across the sets of a
/// multi-set post because [`super::fetch_and_repair`] is per set and
/// hands every set the same vector; a path a LATER set then proves and
/// publishes is simply gone from disk by the time the quarantine reads
/// the list, which `nzbkit::journal::quarantine_paths` skips.
///
/// Called at exactly one moment - see the module header - and its
/// emptiness is what the caller turns back into today's shortfall
/// verdict, so an unproductive pass costs the reader nothing but the
/// wire it says it spent.
pub(super) async fn rescue_payload_posted_as_volume(
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
    nzb: &Nzb,
    out_dir: &Path,
    set: &nzbkit::par2::Par2Set,
    buf_pool: &Arc<nzbkit::pool::BufPool>,
    already_fetched: &[usize],
    cancel: Option<&SideCancel>,
    left_behind: &mut Vec<PathBuf>,
) -> Vec<String> {
    let absent = absent_files(out_dir, set);
    let chosen = payload_shaped_volumes(nzb, already_fetched, &absent);
    if chosen.is_empty() {
        return Vec::new();
    }
    let mut ids: Vec<nzbkit::pool::ArticleReq> = Vec::new();
    let mut id_to_file: std::collections::HashMap<Arc<str>, usize> =
        std::collections::HashMap::new();
    let mut omitted = 0u32;
    for &fi in &chosen {
        omitted = omitted.saturating_add(volume_reqs(nzb, fi, &mut ids, &mut id_to_file));
    }
    let bytes: u64 = chosen
        .iter()
        .fold(0u64, |a, &fi| a.saturating_add(nzb.files[fi].bytes()));
    info!(
        target: "par2",
        "{} declared file(s) are missing entirely and {} skipped recovery volume(s) \
         are the size of one of them - buying {:.1} MB to see whether the payload was \
         posted under a volume's name{}",
        absent.len(),
        chosen.len(),
        bytes as f64 / 1e6,
        if omitted > 0 {
            format!(" ({omitted} repeated article id(s) not re-requested)")
        } else {
            String::new()
        }
    );
    // The completeness the `#[must_use]` on `volume_reqs` is about is
    // NOT this pass's judgement, which is why the count above is
    // reported rather than folded into a verdict: identity here is
    // proved from the BYTES (exact length plus md5-16k), and a volume
    // that came back short fails that proof by construction.
    let paths = match fetch_volume_articles(
        servers,
        ids,
        id_to_file,
        out_dir,
        buf_pool,
        volume_prealloc_cap(nzb),
        cancel,
    )
    .await
    {
        Ok((_failures, paths)) => paths,
        Err(e) => {
            warn!(
                target: "par2",
                "fetching the volume-named candidates failed ({e}) - reporting the \
                 recovery shortfall as it stood"
            );
            return Vec::new();
        }
    };
    let mut rescued: Vec<String> = Vec::new();
    for p in &paths {
        if !publish_if_payload(p, &absent, out_dir, &mut rescued) {
            left_behind.push(p.clone());
        }
    }
    if rescued.is_empty() {
        info!(
            target: "par2",
            "none of the volume-named candidates carried a missing file's bytes - \
             they stay on disk as recovery data, and a failing job renames them \
             aside with the rest of its unverified output"
        );
    }
    rescued
}

#[cfg(test)]
mod tests;
