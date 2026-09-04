//! Every set file classified for the mapped repair route - the gate that
//! decides whether [`super::try_mapped_repair`] can run at all.
//!
//! Its own file rather than a block in repair.rs for `volbase`'s reason.
//! On 31 Aug 2026 that file was at 2,903 of the size gate's 3,000-line
//! ceiling and this was carved out of a function 31 lines under the
//! 500-line FUNCTION ceiling, so keeping the helper inline would have
//! spent 73 of the file's remaining 97 lines to buy the function's
//! margin - which is why it is out here and not lower down the same
//! file. One subject, one caller, and nothing else in the file reaches
//! it.

use super::*;

/// What the gate below learned about one recovery set: the per-file
/// block census the repair solves over, plus the four slot lists the
/// caller's verdict block reads back after the patch. Every field was a
/// local of [`super::try_mapped_repair`] until 31 Aug 2026 and each is
/// still read under its own name there, by destructuring at the call.
pub(super) struct MappedPlan {
    pub(super) files: Vec<(nzbkit::par2::Par2File, Vec<bool>)>,
    pub(super) slot_of: Vec<Option<usize>>,
    pub(super) feed: Vec<Option<(String, u64)>>,
    pub(super) recreated: usize,
    pub(super) chased: Vec<usize>,
    pub(super) chased_damage: Vec<(usize, u64)>,
    pub(super) in_place: Vec<usize>,
    /// One per entry of `files`: the whole-file MD5 the slot's prefix
    /// hasher reached off disk during the download, where damage armed
    /// it (`nzbkit::live::prefix`). The mapped self-prove resumes there
    /// instead of rereading the whole member; `None` everywhere is the
    /// pre-2 Sep 2026 behaviour and always correct.
    pub(super) prefixes: Vec<Option<nzbkit::par2repair::Md5Resume>>,
}

/// Classify every set file for the mapped route, or decline it.
///
/// This was [`super::try_mapped_repair`]'s opening loop until 31 Aug 2026,
/// when that function sat at 469 of the size gate's 500-line ceiling.
/// Nothing about it changed but the shape of a decline - each
/// `return Ok(false)` is a `return None` here, and the caller turns it
/// straight back into `Ok(false)`.
///
/// The anti-preallocation-bomb check rides along at the end, where it has
/// always been: it is a decline like any other and reads the three counts
/// this loop is the only producer of. What does NOT move is the slot
/// allocation - `slot_of` still comes back with a `None` per fresh slot,
/// so the caller allocates only past every cheap decline and a declined
/// call still leaves no stray slots in the extractor.
pub(super) fn plan_mapped_repair(
    set: &nzbkit::par2::Par2Set,
    bs: usize,
    extractor: &nzbkit::extract::Extractor,
    reports: &[(usize, nzbkit::live::SlotReport)],
    missing_files: &[String],
    set_scope: Option<(&[Option<usize>], usize)>,
) -> Option<MappedPlan> {
    use nzbkit::par2repair::{MAX_INPUT_SLICES, MAX_REPAIR_DIM};
    // Gate: every set file must be one of
    //  - verified/damaged with a sane ledger, DAMAGED only if mapped or
    //    plain-patchable (a clean plain file was always fine - read_at
    //    serves it from its writer; a DAMAGED one now patches in place
    //    through the same writer, TODO 160);
    //  - wholly missing (unclaimed, or claimed with every block bad and
    //    not a byte on hand) - rebuilt from parity and FED through the
    //    normal arrival path.
    let mut files: Vec<(nzbkit::par2::Par2File, Vec<bool>)> = Vec::with_capacity(set.files.len());
    // Slot per set file; None = a fresh slot, allocated only after
    // every cheap decline below so a declined call leaves no stray
    // slots in the extractor.
    let mut slot_of: Vec<Option<usize>> = Vec::with_capacity(set.files.len());
    // Some((par2 name, length)) = this file's reconstructed spans FEED
    // through `Extractor::write_repair` instead of `patch_volume_span`.
    let mut feed: Vec<Option<(String, u64)>> = Vec::with_capacity(set.files.len());
    let mut total_slices = 0usize;
    let mut missing_slices = 0usize;
    let mut recreated = 0usize;
    // Chased slots this call intends to patch in place - re-read for
    // the conflict verdict once every rebuilt block has landed.
    let mut chased: Vec<usize> = Vec::new();
    // The same slots with the END of their damage, for the TODO 278
    // ordering hook below. A repair only trips the conflict when it
    // rewrites a byte the decode has already READ, so the hook needs to
    // know which byte to wait for, and this is the only place that
    // knows: `r.bad_blocks` and the set's block size are both in scope
    // here and neither survives into the patch.
    let mut chased_damage: Vec<(usize, u64)> = Vec::new();
    // EVERY slot this call intends to patch in place, chased or not.
    // Each was Rar / Plain / RarChase when the gate below passed it -
    // `is_mapped`, `is_plain_patchable` and `is_chase_patchable` match
    // nothing else - so any of them reading `demoted_to_disk` after the
    // patch demoted DURING it, which deleted the group's extracted
    // output. Same post-check discipline as `chased`, one question
    // wider; see the verdict block after `repair_mapped_catalog`.
    let mut in_place: Vec<usize> = Vec::new();
    let mut prefixes: Vec<Option<nzbkit::par2repair::Md5Resume>> = Vec::new();
    for f in &set.files {
        let n = f.length.div_ceil(set.block_size) as usize;
        total_slices += n;
        // THIS set's reports only, the same `slot_set` guard
        // `dupefill::wanted_files` carries and for the identical reason
        // (read-only sweep finding 9, 31 Aug 2026): the pairing below is
        // by NAME, and settle hands this function the ONE SHARED report
        // list once per set. Two sets of a per-file-set post routinely
        // name the same file - a duplicate posting, or a poster who ran
        // par2create twice over one directory - so a report belonging to
        // set A could be resolved inside set B, patched at B's block
        // size against B's own IFSC table, and then extend `proved` with
        // that NAME, at which point `already_proved` skips the sibling
        // set whose file was never repaired at all.
        //
        // Deliberately `!= Some(idx)` and not `is_some_and(..)`, which
        // is that function's wording too: a slot the verifier cannot
        // place in any set has no set vouching for its block grid, so it
        // is nobody's business rather than everybody's. On a single-set
        // post every report belongs to set 0, so this refuses nothing
        // there - and a call with no verifier behind it (`set_scope`
        // None, the unit rigs) is a single-set world by construction and
        // is left exactly as it was.
        //
        // A report held out here does not silently vanish: the set file
        // it would have matched falls to the `None` arm below, which
        // DECLINES the whole mapped route unless the census independently
        // called that file missing. Declining is the safe direction - the
        // set goes to `disk_repair_declined_sets`, which materializes and
        // re-reads it off disk.
        match reports
            .iter()
            .filter(|(sidx, _)| match set_scope {
                Some((slot_sets, idx)) => slot_sets.get(*sidx).copied().flatten() == Some(idx),
                None => true,
            })
            .find(|(_, r)| r.par2_name.as_deref() == Some(f.name.as_str()))
        {
            Some((sidx, r)) => {
                if r.total_blocks != n || r.bad_blocks.iter().any(|&b| b >= n) {
                    return None;
                }
                // A claimed slot with every block bad and ZERO bytes on
                // hand (a resume-seeded name whose refetch all failed)
                // is a whole-file loss, not damage: nothing to patch
                // through, everything to feed.
                let wholly_missing = n > 0
                    && r.bad_blocks.len() == n
                    && !extractor.is_mapped(*sidx)
                    && extractor.covered_intervals(*sidx, 0, f.length).is_empty();
                if wholly_missing {
                    recreated += 1;
                    feed.push(Some((f.name.clone(), f.length)));
                } else {
                    // Damage patches in place through the slot's own
                    // byte view: the block→payload mapping for a mapped
                    // volume, the output writer for a plain file. Any
                    // other shape - above all a CHASE, whose frontier
                    // buffer cannot take a rewrite - declines the whole
                    // call to the materialize path. A plain file is the
                    // TODO 160 admission: without it, one bad article
                    // in a plain set member demoted every chased volume
                    // beside it to disk and re-extracted them.
                    //
                    if !r.bad_blocks.is_empty() && !extractor.is_mapped(*sidx) {
                        let plain_ok = extractor.is_plain_patchable(*sidx)
                            && plain_patch_keeps_sniff(&r.bad_blocks, bs);
                        // Shape-coverage row 26: a CHASED volume can
                        // take the rewrite too, straight into its
                        // frontier buffer, which is what keeps a damaged
                        // COMPRESSED set off the three-write disk route
                        // (measured 22 Aug 2026 at 3.05x of payload
                        // in device I/O against 1.03x for the same
                        // damage on a store set, and re-measured the
                        // same day at 2.03x with this route taken).
                        // DEFAULT ON since that round; the escape
                        // hatch is `NZBFAST_NO_CHASE_REPAIR=1` - see
                        // `chase_repair_on`.
                        let chase_ok = chase_repair_on() && extractor.is_chase_patchable(*sidx);
                        if !plain_ok && !chase_ok {
                            return None;
                        }
                        if chase_ok {
                            chased.push(*sidx);
                            // Past the LAST bad block, clipped to the
                            // file: a decode that has read that far has
                            // read every byte this repair will rewrite,
                            // so the conflict is settled rather than
                            // still in flight.
                            let last = r.bad_blocks.iter().copied().max().unwrap_or(0);
                            let end = ((last as u64 + 1) * set.block_size).min(f.length);
                            chased_damage.push((*sidx, end));
                        }
                    }
                    if !r.bad_blocks.is_empty() {
                        in_place.push(*sidx);
                    }
                    feed.push(None);
                }
                missing_slices += r.bad_blocks.len();
                let mut present = vec![true; n];
                for &b in &r.bad_blocks {
                    present[b] = false;
                }
                files.push((f.clone(), present));
                prefixes.push(r.prefix_md5.clone());
                slot_of.push(Some(*sidx));
            }
            None => {
                // No slot claimed this file: a par-only post's target,
                // or a posted file whose every article vanished before
                // a name could be learned. Recreate it from parity -
                // with guard rails, since FileDesc name/length are
                // attacker-influenced input reaching a new consumer:
                //  - only files the census actually declared missing;
                //  - no zero-length targets (the disk path makes empty
                //    files; a fed slot with no writes would "verify"
                //    without ever creating one);
                //  - an internally consistent set (IFSC count must
                //    match the declared length);
                //  - posted wins: never a second slot for a name some
                //    output writer or chased slot already carries.
                if !missing_files.iter().any(|m| m == &f.name) {
                    return None;
                }
                if f.length == 0 {
                    return None;
                }
                if !f.blocks.is_empty() && f.blocks.len() != n {
                    return None;
                }
                if !extractor
                    .map_output_range(&nzbkit::disk::sanitize_out_name(&f.name), 0, 1)
                    .is_empty()
                {
                    return None;
                }
                recreated += 1;
                missing_slices += n;
                // The bomb check below runs AFTER this loop, but the
                // allocation is here: `n` comes from a FileDesc length
                // this set declares, and the IFSC cross-check above is
                // skipped when no IFSC packet survived parsing, so a
                // declared length alone can size this vector. Refuse at
                // the same ceiling before reserving anything.
                if missing_slices > MAX_REPAIR_DIM {
                    return None;
                }
                feed.push(Some((f.name.clone(), f.length)));
                files.push((f.clone(), vec![false; n]));
                // A file being recreated WHOLE from parity has no
                // prefix by definition: its first hole is byte 0.
                prefixes.push(None);
                slot_of.push(None);
            }
        }
    }
    // Anti-preallocation-bomb: refuse counts the repair math could
    // never satisfy anyway (a 64 GiB FileDesc over 4 KiB blocks is 16M
    // slices against a 32768-slice format) BEFORE allocating anything.
    if recreated > MAX_RECREATED_FILES
        || total_slices > MAX_INPUT_SLICES
        || missing_slices > MAX_REPAIR_DIM
    {
        return None;
    }
    Some(MappedPlan {
        files,
        slot_of,
        feed,
        recreated,
        chased,
        chased_damage,
        in_place,
        prefixes,
    })
}

#[cfg(test)]
mod scope_tests {
    use super::*;

    fn pfile(name: &str, length: u64) -> nzbkit::par2::Par2File {
        nzbkit::par2::Par2File {
            file_id: [1u8; 16],
            name: name.to_string(),
            length,
            md5: [0u8; 16],
            md5_16k: [0u8; 16],
            blocks: Vec::new(),
        }
    }

    fn pset(files: Vec<nzbkit::par2::Par2File>) -> nzbkit::par2::Par2Set {
        nzbkit::par2::Par2Set {
            recovery_set_id: [0u8; 16],
            block_size: 4096,
            files,
            nonrecovery: Vec::new(),
            recovery_blocks_seen: 0,
        }
    }

    fn report(name: &str) -> nzbkit::live::SlotReport {
        nzbkit::live::SlotReport {
            par2_name: Some(name.to_string()),
            total_blocks: 1,
            bad_blocks: vec![0],
            live_blocks: 0,
            readback_blocks: 0,
            length: 4096,
            prefix_md5: None,
        }
    }

    /// Read-only sweep finding 9 (31 Aug 2026): a report belonging to
    /// ANOTHER set may not be resolved inside this one.
    ///
    /// The pairing here is by NAME, and settle hands this function the
    /// one shared report list once per set - so two sets of a
    /// per-file-set post that name the same file (a duplicate posting, a
    /// poster who ran par2create twice over one directory) cross-bind.
    /// The first matching report wins whatever `slot_set` says, and a
    /// successful repair then extends `proved` with that NAME, at which
    /// point `already_proved` skips the sibling set whose file was never
    /// repaired at all. `dupefill::wanted_files` has carried this guard
    /// since TODO 311; this function did not.
    ///
    /// Three legs off ONE set of inputs, so only the SCOPE differs:
    /// bound where the slot is ours, and where it is not, held out -
    /// shown twice, because a hold-out that merely declined the call
    /// would be indistinguishable from any other decline.
    #[test]
    fn a_report_from_a_sibling_set_is_not_this_sets_business() {
        let dir = std::env::temp_dir().join(format!("nzbfast-mapscope-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ex = nzbkit::extract::Extractor::new(&dir, 8, true);
        let set = pset(vec![pfile("shared.bin", 4096)]);
        let reports = vec![(7usize, report("shared.bin"))];
        // Slot 7 belongs to set 1 as far as the verifier is concerned.
        let slot_sets: Vec<Option<usize>> = vec![None, None, None, None, None, None, None, Some(1)];

        // OURS: the report binds, and the wholly-missing arm recreates.
        let mine = plan_mapped_repair(&set, 4096, &ex, &reports, &[], Some((&slot_sets, 1)))
            .expect("this set's own report must bind");
        assert_eq!(mine.slot_of, vec![Some(7)], "bound to the reporting slot");
        assert_eq!(mine.recreated, 1);

        // NOT OURS, and the census never called the file missing: with
        // no report to resolve, the file falls to the `None` arm and the
        // whole mapped route declines to the disk lane. That is the safe
        // direction, and it is what the sibling set's report was buying
        // before this guard existed.
        assert!(
            plan_mapped_repair(&set, 4096, &ex, &reports, &[], Some((&slot_sets, 0))).is_none(),
            "a sibling set's report must not be resolved inside this set"
        );

        // NOT OURS, census-declared missing: the plan is built WITHOUT
        // the foreign slot, which is the assertion a decline cannot make.
        let theirs = plan_mapped_repair(
            &set,
            4096,
            &ex,
            &reports,
            &["shared.bin".to_string()],
            Some((&slot_sets, 0)),
        )
        .expect("a declared-missing file recreates from parity");
        assert_eq!(
            theirs.slot_of,
            vec![None],
            "the foreign slot must not be adopted - a fresh slot is allocated instead"
        );

        // The unscoped call is unchanged: one set, no verifier, binds.
        let unscoped = plan_mapped_repair(&set, 4096, &ex, &reports, &[], None)
            .expect("an unscoped call is a single-set world and binds as before");
        assert_eq!(unscoped.slot_of, vec![Some(7)]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
