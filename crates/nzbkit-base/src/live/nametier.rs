//! The finish-time NAME tier: what a poster's name is still worth once
//! the slot's whole file is on disk.
//!
//! `try_match` (in the parent) lets a name NOMINATE a descriptor and
//! never finalize one; this is where a nomination the head could not
//! settle is either proved on content or dropped. Both entry points -
//! `settle_binding` for a binding already made, `try_match_named` for a
//! slot that never bound - run ONLY from `finish_slot_from`, because
//! both need bytes that do not exist before then.
//!
//! Split out of `live.rs` (TODO 106 size gate), bodies verbatim; a child
//! module, so `SlotState`'s private fields stay private to this file's
//! parent and its descendants.

use super::*;

impl SlotState {
    /// Settle a tentative binding at finish, with the slot's bytes
    /// available: confirm it on content, or drop it.
    ///
    /// TWO NOMINATIONS ARRIVE HERE AND THEY ARE SETTLED DIFFERENTLY. A
    /// NAME's is settled by the arms below, the head among them, because
    /// the head is content the name knows nothing about. A HEAD's
    /// ([`SlotState::head_nominated`], M4-103) is settled by
    /// [`head_nomination_holds`](Self::head_nomination_holds) instead:
    /// there the head is the evidence the binding was already made on,
    /// so it - and every block inside it - has to be spent, not counted
    /// twice.
    ///
    /// Confirmation is any ONE of - a block of the nominated descriptor
    /// present in these bytes (the same evidence [`ifsc_evidence`]
    /// states, and what a truthfully-named DAMAGED member always
    /// shows), its whole-file MD5, or its own 16k head where that head
    /// is UNSHARED. Shared is the qualifier that matters: a binding
    /// taken from several head-confirmed candidates is a pairing, and a
    /// pairing the blocks and the whole file both refuse is one to drop
    /// so the whole-file tier can re-make it, not one to bless on the
    /// 16 KiB the candidates agree about.
    ///
    /// Dropping needs POSITIVE denial, not merely an absence: the head
    /// read from `src` has to disagree. A slot whose bytes cannot be read
    /// at all - every article of the file failed - keeps its nomination
    /// and is reported as the damaged member it is, which is the answer
    /// the name-first matcher gave before the nomination rule existed.
    /// What is dropped is the file that IS readable, in full, and matches
    /// the descriptor nowhere: an uncovered payload posted under a set
    /// member's name (W4-18), which claiming would fail the whole job on.
    pub(super) fn settle_binding(
        &mut self,
        slot: usize,
        active: &Active,
        src: &ReadAt<'_>,
    ) -> bool {
        let Some(fi) = self.file else {
            return false;
        };
        if self.confirmed {
            return true;
        }
        let f = active.file(fi);
        let bs = active.block_size(fi) as usize;
        if self.head_nominated {
            // A HEAD NOMINATION IS NOT SETTLED BY THE HEAD (M4-103). The
            // arms below all treat the 16 KiB digest as fresh evidence,
            // and for this shape it is the evidence the binding was
            // already made on - re-reading it proves only that the digest
            // still matches, and `ifsc_evidence` is no better, because a
            // head two files share is whole BLOCKS they share.
            if !self.head_nomination_holds(f, src) {
                tracing::warn!(
                    target: "par2",
                    "slot {slot} opens with {:?}'s first 16k, carries none of that \
                     file's blocks past the run they share, and is not that file \
                     whole either - leaving it out of the recovery set rather than \
                     renaming an uncovered payload onto a member",
                    f.name,
                );
                return false;
            }
            let mut claimed = active.claimed.lock_ok();
            // The nomination took the claim when it was made, so OURS is
            // the one that may be here; anything else means the real
            // owner got there by content while we verified.
            if claimed[fi].is_some_and(|o| o != slot) {
                return false;
            }
            claimed[fi] = Some(slot);
            self.confirmed = true;
            self.head_nominated = false;
            return true;
        }
        // The descriptor's OWN 16k span, not the slot's declared one -
        // at finish the bytes are there to read, so the mismatch
        // `head_says` has to call Unknown in-stream does not arise.
        let want = f.length.min(HEAD_LEN as u64) as usize;
        let head = if want == 0 {
            None
        } else {
            src_head_md5(src, want).ok()
        };
        let proved = match head {
            // No readable head: nothing denied the name, so the
            // nomination stands (see the note above) - and it stands
            // BEFORE the block probe, which is the only expensive arm
            // here and would be paying to confirm what is already
            // settled.
            None => true,
            // Cheapest conclusive arm first, and the whole-file read
            // LAST: it is only ever reached for a candidate whose head
            // is shared and whose blocks all refused, which is the twin
            // mispairing - exactly the question `try_match_whole` would
            // read the file for anyway.
            Some(h) => {
                ifsc_evidence(src, f, bs)
                    || (h == f.md5_16k && !head_is_shared(active, fi, want, h))
                    || src_md5(src, f.length).is_ok_and(|m| m == f.md5)
            }
        };
        if !proved {
            tracing::warn!(
                target: "par2",
                "slot {slot} arrived under the name {:?} but carries none of that \
                 file's bytes - leaving it out of the recovery set rather than \
                 verifying the set's file against a different payload",
                f.name
            );
            return false;
        }
        let mut claimed = active.claimed.lock_ok();
        if claimed[fi].is_some() {
            // Its real owner claimed it by content while we verified.
            return false;
        }
        claimed[fi] = Some(slot);
        self.confirmed = true;
        true
    }

    /// Does anything this slot actually received contradict the
    /// descriptor its first 16 KiB nominated (M4-103)?
    ///
    /// THE HEAD IS SPENT EVIDENCE. It is what made the binding, so
    /// nothing derived from it can finalize one: not the digest itself,
    /// and not the blocks inside it either - two files sharing a
    /// zero-filled head share whole BLOCKS of zeros, and every one of
    /// them verifies Ok against the descriptor while identifying
    /// nothing. The row's own e2e fixture is 200 such blocks, and its
    /// shared run does not stop at 16 KiB, so "look past the head" is
    /// not the rule either.
    ///
    /// WHAT THE SHAPE ACTUALLY IS: an impostor matches a PREFIX and then
    /// never matches again. Damage does not look like that, and the
    /// reason is structural rather than statistical - a member is
    /// damaged because ARTICLES ARE MISSING, and a block no article
    /// covered is `Pending`, never `Bad`. So the real bytes on the far
    /// side of a hole still match, and a hole is silence rather than
    /// denial, which is `settle_binding`'s own rule. A block goes `Bad`
    /// only when its bytes were DELIVERED IN FULL and are not the
    /// descriptor's.
    ///
    /// So: deny when this slot's blocks stopped matching and never
    /// matched again. One matching block anywhere past the first
    /// mismatch holds the nomination - which keeps the member whose
    /// bytes were corrupted in transit (lean mode skips the article
    /// CRC, so such a block does land and does fail) and keeps every
    /// shape where the damage is holes. No threshold and no fraction:
    /// the question is whether the evidence ever came back, not how much
    /// of it there is.
    ///
    /// AND THE DENIAL IS NOT VACUOUS. A first mismatch with nothing
    /// DELIVERED after it says only that the slot ends there, which is
    /// what a member whose last article was corrupted looks like, so it
    /// holds. Something has to have arrived past the mismatch and failed
    /// for this to be the prefix signature at all.
    ///
    /// THE BLOCKS ARE NOT THE LAST WORD, because the IFSC itself can be
    /// the thing that is wrong. M4-69's two rows are a byte-exact
    /// download whose set carries FORGED block checksums - every block
    /// arrives and every one fails - which is the prefix signature with
    /// an empty prefix, and denying it would take a file the FileDesc
    /// MD5 proves intact out of its own recovery set. So a signature
    /// that looks like an impostor escalates to the whole-file MD5, the
    /// strongest evidence a settled file admits and the same escalation
    /// `finish_slot_from` runs for the same reason. It is only ever
    /// reached on suspicion: a healthy member holds on its blocks and
    /// reads nothing, and the two M4-103 fixtures never hash a byte
    /// either, because `src_md5` pins the source's length first and
    /// neither impostor has the descriptor's.
    ///
    /// THE OBVIOUS RULE WAS BUILT, MEASURED AND REFUSED, and it is worth
    /// knowing why before anyone reaches for it again. "The slot settled
    /// at exactly its own declared size, so its length IS that size, and
    /// the descriptor declares another" reads like a measurement and is
    /// not one HERE: `get` preallocates the output file at the yEnc
    /// declared size, so on the only source production ever hands this
    /// function the extent is that size BY CONSTRUCTION and the test
    /// collapses to `f.length != self.file_size` - the bare length
    /// comparison the row prices and refuses. It went red on
    /// `e2e_norar::lying_yenc_size_lands_at_the_filedesc_length`, matrix
    /// finding F5, where the poster overstates `size=` by 77,777 bytes
    /// while every `=ypart` range and every block is honest.
    ///
    /// STATED LIMIT, which is the residue the row already names: two
    /// files of the SAME length sharing a head still cross, where the
    /// impostor's blocks past the shared run all happen to be
    /// undelivered. Nothing at this seam separates that from a damaged
    /// member - which is the safe direction for the member.
    fn head_nomination_holds(&self, f: &crate::par2::Par2File, src: &ReadAt<'_>) -> bool {
        let Some(bad) = self.blocks.iter().position(|b| *b == BlockState::Bad) else {
            // Nothing this slot delivered contradicts the descriptor.
            return true;
        };
        let after = &self.blocks[bad + 1..];
        if after.contains(&BlockState::Ok) || !after.contains(&BlockState::Bad) {
            return true;
        }
        src_md5(src, f.length).is_ok_and(|m| m == f.md5)
    }

    /// Name tier of last resort, at finish, with the slot's bytes on
    /// disk - the half that keeps "a name is only a nomination" from
    /// costing a truthfully-named DAMAGED file its claim.
    ///
    /// [`try_match`](Self::try_match) declines a name its head key
    /// denies, and declines every name while the head is still filling.
    /// Both shapes are ordinary: a file damaged inside its own first
    /// 16 KiB denies, and a file whose first article never arrived has no
    /// head at all. Under the old exact-first rule each of those claimed
    /// on the name and was repaired in place; declining them and stopping
    /// there would price a repairable member as WHOLLY MISSING, which
    /// needs many times the recovery blocks the damage does and turns a
    /// repairable job unrepairable. So the nomination comes back here,
    /// and content settles it with the whole file available:
    ///
    ///   * the head read from `src` over `min(16 KiB, candidate length)`
    ///     - which sidesteps the declared-size mismatch `head_says` has
    ///     to call `Unknown` in-stream - confirms exactly one candidate;
    ///   * failing that, a SOLE candidate is claimed only on per-block
    ///     IFSC evidence: any one of its blocks present in this slot's
    ///     bytes. A damaged member shows its intact blocks on the first
    ///     probe or two; a different file wearing the name shows none,
    ///     which is what keeps an uncovered payload posted honestly under
    ///     a set member's name out of the set (W4-18).
    ///
    /// Ambiguity is never settled here: two candidates and no head
    /// confirmation stay unclaimed, exactly as the in-stream tiers leave
    /// them.
    pub(super) fn try_match_named(
        &mut self,
        slot: usize,
        active: &Active,
        src: &ReadAt<'_>,
    ) -> bool {
        if self.file.is_some() {
            return false;
        }
        let name = match &self.name {
            Some(n) => n.clone(),
            None => return false,
        };
        let fold = name.to_ascii_lowercase();
        let sname = crate::disk::sanitize_out_name(&name);
        let cands: Vec<usize> = {
            let claimed = active.claimed.lock_ok();
            let folded: &[usize] = active.by_fold.get(fold.as_str()).map_or(&[], |v| v);
            let exact: Vec<usize> = folded
                .iter()
                .copied()
                .filter(|&fi| claimed[fi].is_none() && active.file(fi).name == name)
                .collect();
            if !exact.is_empty() {
                exact
            } else {
                let sanit: &[usize] = active.by_sanitized.get(sname.as_str()).map_or(&[], |v| v);
                let mut v: Vec<usize> = folded
                    .iter()
                    .chain(sanit.iter())
                    .copied()
                    .filter(|&fi| claimed[fi].is_none())
                    .collect();
                v.sort_unstable();
                v.dedup();
                v
            }
        };
        if cands.is_empty() {
            return false;
        }
        // One head read per DISTINCT candidate length (the common case is
        // one), against the descriptor's own 16k span rather than the
        // slot's declared one.
        let mut cached: Option<(usize, [u8; 16])> = None;
        let mut confirmed: Vec<usize> = Vec::new();
        // A head the source cannot serve DENIES NOTHING - the file is
        // short of the descriptor's own 16k span, which is what a member
        // whose first articles never arrived looks like. Only a head that
        // was read and disagreed is evidence against the name.
        let mut head_unreadable = false;
        for &fi in &cands {
            let n = active.file(fi).length.min(HEAD_LEN as u64) as usize;
            if n == 0 {
                continue;
            }
            let h = match cached {
                Some((l, h)) if l == n => h,
                _ => match src_head_md5(src, n) {
                    Ok(h) => {
                        cached = Some((n, h));
                        h
                    }
                    Err(_) => {
                        head_unreadable = true;
                        continue;
                    }
                },
            };
            if h == active.file(fi).md5_16k {
                confirmed.push(fi);
            }
        }
        // Confirmed-plural means byte-identical heads; the whole file is
        // the only thing left that can tell them apart, and a candidate a
        // twin raced us to simply falls through to the next.
        // X5-21, and the reason this loop keeps a SUCCESS-only cache
        // where `try_match_whole`'s remembers a failure too: that tier's
        // candidates are grouped by 16 KiB HEAD, so a producer decides
        // how many there are and a repeated doomed length was re-read
        // once per member. These are grouped by NAME and already head-
        // confirmed, so the group is the handful of descriptors wearing
        // one name. What covers the rest is one level down: `src_md5`
        // pins the source's length with two one-byte probes before it
        // hashes anything, so a candidate this cache misses costs two
        // bytes rather than a whole file.
        let ordered: Vec<usize> = if confirmed.len() == 1 {
            confirmed
        } else if confirmed.len() > 1 {
            let mut whole: Option<(u64, [u8; 16])> = None;
            let mut keep = Vec::new();
            for fi in confirmed {
                let f = active.file(fi);
                let got = match whole {
                    Some((l, h)) if l == f.length => h,
                    _ => match src_md5(src, f.length) {
                        Ok(h) => {
                            whole = Some((f.length, h));
                            h
                        }
                        Err(_) => continue,
                    },
                };
                if got == f.md5 {
                    keep.push(fi);
                }
            }
            if keep.len() == 1 { keep } else { Vec::new() }
        } else if cands.len() == 1 {
            let fi = cands[0];
            let bs = active.block_size(fi) as usize;
            if head_unreadable || ifsc_evidence(src, active.file(fi), bs) {
                vec![fi]
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };
        for fi in ordered {
            let mut claimed = active.claimed.lock_ok();
            if claimed[fi].is_some() {
                continue;
            }
            claimed[fi] = Some(slot);
            self.file = Some(fi);
            self.confirmed = true;
            self.blocks = vec![BlockState::Pending; active.file(fi).blocks.len()];
            return true;
        }
        false
    }
}

/// Does any OTHER unclaimed descriptor open with the same 16 KiB?
///
/// The question [`SlotState::settle_binding`] needs before it lets a
/// head confirm a binding: an unshared head identifies the file, a
/// shared one only narrows it to the group, and telling that group
/// apart is [`SlotState::try_match_whole`]'s job.
fn head_is_shared(active: &Active, fi: usize, want: usize, key: [u8; 16]) -> bool {
    let claimed = active.claimed.lock_ok();
    active.files().any(|(gi, g)| {
        gi != fi && claimed[gi].is_none() && head_says(g, want, key) == HeadSays::Confirm
    })
}

/// MD5 of the first `n` bytes of `src` - the finish-time head read
/// [`SlotState::try_match_named`] arbitrates by. Fails when the source
/// cannot serve `n` bytes, which is itself an answer (a file short of a
/// candidate's own 16k span is not that candidate).
fn src_head_md5(src: &ReadAt<'_>, n: usize) -> io::Result<[u8; 16]> {
    let mut buf = vec![0u8; n];
    match src {
        ReadAt::Missing => return Err(io::Error::new(io::ErrorKind::NotFound, "no data")),
        ReadAt::Path(path) => {
            let f = std::fs::File::open(path)?;
            crate::disk::read_exact_at(&f, &mut buf, 0)?;
        }
        ReadAt::Reader(r) => r(0, &mut buf)?,
    }
    Ok(Md5::digest(&buf).into())
}

/// Does this slot's data carry ANY block of `file`'s IFSC?
///
/// The evidence [`SlotState::try_match_named`] needs to tell a
/// truthfully-named DAMAGED member (its intact blocks are right there)
/// from a different file wearing the name (not one block of it will
/// ever check out). One matching block is the whole bar: a block passes
/// only on CRC32 **and** MD5 over the padded slice, so a coincidence is
/// not a thing that happens - and asking for a FRACTION instead would
/// have to name a number, which is exactly the arbitrary threshold a
/// heavily damaged member would then fall the wrong side of.
///
/// Probes are STRIDED rather than sequential (damage clusters) and
/// bounded twice, by probe count and by bytes read, because this runs
/// only on the rare denied-or-headless nomination and must not turn one
/// lying name on a large file into an unbounded read.
///
/// The read loop itself is [`twintier::probe_blocks`](super::twintier::probe_blocks) -
/// the twin tier's per-block matcher for N identical-head candidates,
/// called here with the single candidate `file` and a `stop_early` that
/// fires the moment one block matches, so a lying name on a large file
/// still stops at the first hit rather than reading every probe.
fn ifsc_evidence(src: &ReadAt<'_>, file: &crate::par2::Par2File, bs: usize) -> bool {
    block_evidence(src, file, bs).1 > 0
}

/// [`ifsc_evidence`] with the counts kept rather than collapsed:
/// `(blocks actually READ, blocks that matched)`.
///
/// The two numbers are a different question from the boolean, and the
/// difference is `settle_binding`'s own rule one seam further out:
/// DROPPING A NAME NEEDS POSITIVE DENIAL, NOT MERELY AN ABSENCE. A file
/// whose bytes cannot be read at all - every article of it failed -
/// answers `(0, 0)`, which is silence and not a denial, and a caller
/// that read the boolean alone could not tell it from a file that was
/// read in full and matched nowhere. `probe_blocks` records a block
/// only when the read SUCCEEDED, so the first number is exactly the
/// evidence that was available to deny with.
///
/// The public door onto this is [`declared_block_evidence`] just below,
/// re-exported from `live` - which is what `nzbfast`'s repair planner
/// asks before it will treat a file wearing one of the set's own names
/// as an adoption candidate.
pub(super) fn block_evidence(
    src: &ReadAt<'_>,
    file: &crate::par2::Par2File,
    bs: usize,
) -> (usize, usize) {
    if file.blocks.is_empty() || bs == 0 {
        return (0, 0);
    }
    let decls = [&file.blocks[..]];
    let probe =
        super::twintier::probe_blocks(src, file.length, bs, file.blocks.len(), &decls, |hit| {
            hit[0]
        });
    (probe.len(), probe.iter().filter(|(_, hit)| hit[0]).count())
}

/// How much of `f`'s own IFSC the file at `path` answers to:
/// `(blocks actually READ, blocks that matched)`.
///
/// The public door onto the finish-time name tier's strong-evidence
/// test, for the one caller outside this crate that has to ask the same
/// question at a different seam: `nzbfast`'s repair planner, deciding
/// whether a file wearing one of the recovery set's OWN declared names
/// is nevertheless something the adoption scan should read (follow-up
/// 13a-3). The name is a weak clue; a block that checks out is the
/// strong one, and this is the strong one, bounded.
///
/// READ BOTH NUMBERS. `(0, 0)` is SILENCE - nothing of the file could
/// be read, which is what a member whose every article failed looks
/// like - and is never a denial. Only `read > 0 && hit == 0` says the
/// file was there to be judged and is not this descriptor's. That is
/// [`SlotState::settle_binding`]'s own rule ("dropping needs
/// positive denial, not merely an absence"), and a caller that
/// collapses the pair loses it.
///
/// THE REPAIR PLANNER ASKS ONLY THE FIRST NUMBER, and has since
/// follow-up 13a-4 (31 Aug 2026), so do not read the sentence above as
/// a description of that caller. It reaches this door only for a file
/// whose ON-DISK LENGTH is not the descriptor's, and such a file cannot
/// be INTACT whatever verifies inside it - so there a hit does not mean
/// "leave it alone", it means identified and damaged, which is a target
/// `par2repair`'s last-resort escalation scans rather than skips. `hit`
/// carries no information at that seam; `read > 0` is the whole
/// question ("were there bytes here to read"), and the silence rule is
/// what keeps an unreadable member out. The pair is NOT vestigial: the
/// denial reading is the right one wherever identification has not
/// already been settled by other means, which is why both numbers are
/// still returned rather than one.
///
/// Bounded twice - by probe count and by bytes read - and STRIDED, so
/// one lying name on a disk image cannot turn this into an unbounded
/// read; it stops at the first matching block, so the ordinary
/// truthfully-named damaged member costs a block or two.
pub fn declared_block_evidence(
    path: &std::path::Path,
    f: &crate::par2::Par2File,
    bs: usize,
) -> (usize, usize) {
    block_evidence(&ReadAt::Path(path), f, bs)
}
