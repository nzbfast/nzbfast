//! The whole inherent impl of [`SlotState`] - one live slot's head
//! capture, the nomination it feeds the name and twin tiers, and the
//! unbind that hands its counters back.
//!
//! One subject read three ways. WHAT THE SLOT HAS SEEN: `empty`,
//! `head_want` and `capture_head` accumulate the complete-head window
//! the whole name tier is decided on, and `head_key` digests it. WHAT
//! IT MAY BE: `refused` is the cheap no, and `try_match` is the full
//! arbitration against one `Active` plan, tier by tier. WHAT IT LEAVES
//! BEHIND: `unbind` takes the live counters and the partial bytes back
//! out when a binding turns out to be wrong.
//!
//! Its own file for the reason `live/blockcheck.rs` and
//! `live/headarb.rs` are: one subject per file (TODO 106, the
//! code-quality refactor). The same shape
//! `par2repair/reconstruct.rs` takes for `Reconstructor` - the impl
//! moves, [`SlotState`] itself stays in the parent beside its field
//! docs, which is where a reader looks for what a field means.
//!
//! A child module of the defining module, reached by `#[path]` from
//! live.rs, so the struct's private fields and live.rs's own private
//! helpers and `use` bindings (`runs::{CrcParts, Partial, PartialBuf}`,
//! the blockcheck primitives, the three name/twin tiers) stay in scope
//! exactly as they were inline. `fn` became `pub(super) fn` for every
//! method here, because a private inherent method in a child is not
//! visible to the parent that calls it - that visibility is the only
//! thing this move changed.

use super::*;

impl SlotState {
    pub(super) fn empty() -> SlotState {
        SlotState {
            name: None,
            name_keys: None,
            head: None,
            head_md5: None,
            file_size: 0,
            file: None,
            confirmed: false,
            head_nominated: false,
            head_rival_ruled_out: false,
            blocks: Vec::new(),
            bind_gen: 0,
            partials: HashMap::new(),
            partial_bytes: 0,
            pre_spans: Vec::new(),
            resume_seeded: false,
            pre_unvouched: false,
            unmatchable: None,
            live_ok: 0,
            live_bad: 0,
            ok_prefix: 0,
            vouch: None,
            readback_forced: Vec::new(),
            ifsc_self_contradicted: false,
        }
    }

    pub(super) fn head_want(&self) -> usize {
        if self.file_size > 0 {
            // Clamp in u64 BEFORE narrowing: `self.file_size as usize`
            // truncates a >4 GiB file on a 32-bit target, so a 4 GiB + 10
            // byte file asked for a 10-byte head.
            self.file_size.min(HEAD_LEN as u64) as usize
        } else {
            HEAD_LEN
        }
    }

    pub(super) fn capture_head(&mut self, offset: u64, data: &[u8]) {
        let want = self.head_want();
        // In u64: `offset as usize` wrapped on a 32-bit target, so an
        // article at 4 GiB + 16 read as offset 16 and its bytes were
        // captured as the head of the file.
        if want == 0 || offset >= want as u64 {
            return;
        }
        let head = self.head.get_or_insert_with(|| Partial::new(want));
        if head.buf.len() != want {
            // file_size learned after the first capture changed `want`.
            //
            // NEITHER DIRECTION MAY DISCARD A BYTE, and that is one rule
            // rather than two cases: every byte in this buffer was
            // written at the file offset its own article declared, so
            // the buffer is always a true PREFIX of the file and a
            // prefix stays true whatever the length turns out to be.
            // What changes is only how much of it the digest covers.
            if want > head.buf.len() {
                // GROW, never restart, when `want` only got bigger -
                // which since W4-11 is the ordinary case: a later
                // article disproves an under-declared `size=` and the
                // head this slot needs gets longer. The bytes already
                // captured are still the file's FIRST bytes and their
                // intervals still describe them, so discarding them
                // would strand a slot whose offset-0 article has already
                // been consumed and can never be re-fed - the head would
                // then never complete and the content tier would be dead
                // for that slot for the rest of the run.
                head.buf.resize(want, 0);
            } else {
                // M4-94: SHRINK, which the grow arm above cannot reach
                // and which restarted from empty until 31 Aug 2026 -
                // "rare, only when the very first article lacked a
                // size" was the note on it, and that is precisely the
                // shape it broke. `file_size` is monotone once nonzero
                // (W4-11 raises it, never lowers it), so the only way
                // `want` gets SMALLER is the 0 -> nonzero latch: an
                // article omitting `size=` captures its bytes under the
                // full 16 KiB `want`, and the first article to declare a
                // length below that shrinks it. The restart threw those
                // offset-0 bytes away, and the offset-0 article has by
                // then been consumed and can never be re-fed - so the
                // head never completed again, `head_key` stayed `None`
                // for the rest of the run, and the md5-16k tier (the
                // ONLY identity an obfuscated post has) was dead for
                // that slot. Measured on an INTACT 20 KB file whose
                // second article declared 8192: unclaimed, where the
                // same spans with honest sizes claim.
                //
                // Truncation is what the prefix argument above buys:
                // bytes 0..want are already the right bytes, and the
                // intervals are clipped to match. `filled` is sorted and
                // merged, and clipping a sorted merged list to a prefix
                // keeps it sorted and merged, so `complete()` still
                // recognises a filled head as the single span
                // `[(0, want)]`.
                //
                // The head is NOT held at a high-water mark instead:
                // PAR2's `md5_16k` covers the first 16 KiB OR THE WHOLE
                // FILE IF SHORTER, so a genuinely 5000-byte file must
                // hash exactly 5000 bytes. A `want` that refused to
                // shrink would hash 5000 real bytes plus 11384 zeros and
                // match nothing, which trades this defect for a wider
                // one.
                head.truncate(want);
            }
            // The cached digest described the OLD span. Leaving it would
            // let `head_key` answer about bytes this slot no longer holds,
            // and the rival latch is an answer ABOUT that digest.
            self.head_md5 = None;
            self.head_rival_ruled_out = false;
            // ...and so is the permanent refusal, which is the half W4-11
            // turned up. `unmatchable` means "this head, hashed whole,
            // matched no descriptor"; a head that has just got LONGER is
            // not that head, and the digest the refusal was reached on no
            // longer exists. Left latched it froze the slot for the rest
            // of the run - `on_data` returns before matching and
            // `finish_slot` skips the whole-file and named tiers too - so
            // an under-declared `size=` on the article that happened to
            // arrive first was a permanent verdict about a file that was
            // merely described short. Cleared here rather than weakened
            // at the latch site so every slot whose head never changes
            // keeps exactly the behaviour it had.
            self.unmatchable = None;
        }
        if head.complete() {
            return;
        }
        // Proven < `want` (a few KiB) by the guard above, so this narrows
        // on every target.
        let off = offset as usize;
        let end = (off + data.len()).min(want);
        if end > off {
            head.fill(off, &data[..end - off]);
        }
    }

    /// The MD5 of this slot's captured head, once the head is COMPLETE -
    /// the content key every name tier is arbitrated by. `None` means
    /// "no evidence yet", never "no evidence ever": the head fills
    /// interval-wise, so a slot whose first article has not landed
    /// simply has not been judged.
    ///
    /// Cached because an unmatched slot re-matches on every article and a
    /// denied name never becomes matchable, so the digest would otherwise
    /// be recomputed per article for the whole run.
    pub(super) fn head_key(&mut self) -> Option<[u8; 16]> {
        if self.head_md5.is_some() {
            return self.head_md5;
        }
        let want = self.head_want();
        if want == 0 {
            return None;
        }
        let h = self.head.as_ref()?;
        if h.buf.len() != want || !h.complete() {
            return None;
        }
        self.head_md5 = Some(Md5::digest(&h.buf).into());
        self.head_md5
    }

    /// Is this slot's permanent refusal still ABOUT the descriptors now
    /// live?
    ///
    /// Every site that skips a match tier because the slot "will never
    /// match" asks this rather than reading the field, because a refusal
    /// reached before a second recovery set was adopted is a refusal
    /// about descriptors that are no longer the whole of what there is
    /// to match against. [`Active::adopted_gen`] moves exactly when the
    /// adopted set list grows, so a stale latch re-opens the slot for one
    /// more pass and [`try_match`](Self::try_match) re-latches it at the
    /// current generation if the answer has not changed.
    pub(super) fn refused(&self, active: &Active) -> bool {
        self.unmatchable == Some(active.adopted_gen)
    }

    /// Try to claim a PAR2 file for this slot. Name NOMINATES, content
    /// FINALIZES; md5-16k second. Requires `self.file.is_none()`.
    ///
    /// A NAME IS A NOMINATION AND NEVER A PROOF (W4-02, 30 Aug 2026).
    /// The exact tier used to `find` the first unclaimed descriptor with
    /// a matching name and claim it on the spot, ahead of every content
    /// tier. yEnc names are attacker- and poster-controlled, so that made
    /// three measured failures out of one seam: two intact payloads whose
    /// yEnc names are CROSSED each claimed the other's descriptor and both
    /// verified 1000/1000 blocks bad, so an intact post died unrepairable
    /// at r=10; two descriptors sharing one exact name with distinct
    /// content were settled by FileDesc order, which is arrival-order
    /// dependent and paid a full phantom repair on the losing run; and an
    /// UNCOVERED file posted honestly under a name the set also uses was
    /// claimed by the set, verified all-bad and failed the whole job.
    ///
    /// So the head key arbitrates every name candidate:
    ///   * exactly one candidate CONFIRMED by the head - claim it;
    ///   * several confirmed (identical heads) - the first, bound
    ///     TENTATIVELY, since a shared 16 KiB head is not a shared file;
    ///   * none confirmed but exactly one INCOMPARABLE (the descriptor's
    ///     `md5_16k` covers a different span than this slot's head, so the
    ///     digests can never be equal) - claim it ONLY where the head is
    ///     the SHORTER of the two spans and so is genuinely silent about
    ///     the descriptor, which is the pre-W4-02 answer for that shape.
    ///     Where the head is the LONGER it covers the descriptor whole
    ///     and proves the slot holds more bytes than the descriptor's
    ///     whole file, so it is a decline (F12, see `arbitrate_by_head`);
    ///   * every candidate DENIED - decline, and let the md5-16k tier
    ///     below find the descriptor the content actually names.
    /// A DENIAL NEVER LATCHES `unmatchable`: a truthfully-named file
    /// damaged inside its own first 16 KiB denies too, and
    /// [`try_match_named`](Self::try_match_named) settles that one at
    /// finish on per-block IFSC evidence.
    ///
    /// Nothing here throws the nomination away. What the head has not
    /// settled is bound TENTATIVELY instead (see
    /// [`SlotState::confirmed`]): the first candidate while the head is
    /// still filling, the sole candidate the head denied. The slot
    /// verifies its blocks against it exactly as a claim would, so
    /// out-of-order arrival still costs zero read-back and the ordinary
    /// post is untouched - but it takes no claim, so a crossed pair
    /// locks nothing out and each slot's md5-16k tier still finds the
    /// descriptor its CONTENT names. The first Ok block promotes the
    /// binding to a claim; the head completing RE-JUDGES it
    /// ([`LiveVerifier::rejudge_binding`]), which is what makes the
    /// crossed answer independent of which article landed first; and one
    /// that never earns a promotion is settled at finish by
    /// [`settle_binding`](Self::settle_binding).
    ///
    /// `tentative` is false at finish: by then the whole file is
    /// available, so a nomination is either proved or dropped and there
    /// is nothing left for a provisional binding to wait for.
    pub(super) fn try_match(&mut self, slot: usize, active: &Active, tentative: bool) -> bool {
        let head_key = self.head_key();
        let mut claimed = active.claimed.lock_ok();

        let mut name_ambiguous = false;
        let mut nominee: Option<usize> = None;
        if let Some(name) = &self.name {
            // EXACT first, across the whole set, before any approximate
            // tier is allowed to claim. One first-hit loop over the
            // three match classes let an approximate claim consume a
            // FileDesc whose exact owner had not arrived yet: with
            // slots A.txt and a.txt on a case-sensitive filesystem and
            // FileDesc order [a.txt, A.txt], whichever slot matched
            // first claimed the OTHER file's descriptor case-
            // insensitively and both ended crossed - each verifying,
            // repairing and publishing under the other's name, up to
            // and including one rename unlinking the other's inode
            // (Codex sweep 13 Aug R1).
            let (fold, sname) = self.name_keys.get_or_insert_with(|| {
                (
                    name.to_ascii_lowercase(),
                    crate::disk::sanitize_out_name(name),
                )
            });
            let folded: &[usize] = active.by_fold.get(fold.as_str()).map_or(&[], |v| v);
            let sanit: &[usize] = active.by_sanitized.get(sname.as_str()).map_or(&[], |v| v);
            let exact: Vec<usize> = folded
                .iter()
                .copied()
                .filter(|&fi| claimed[fi].is_none() && active.file(fi).name == **name)
                .collect();
            // Approximate (case-folded or sanitized) only when the exact
            // tier produced NO candidate at all, and only when it is
            // UNIQUE among the unclaimed descriptors. Two candidates is
            // ambiguity, not a choice for FileDesc order to make: leave
            // the slot unclaimed and let the md5-16k fallback below
            // settle it by content. The two sorted candidate lists are
            // merge-walked with dedup so a descriptor matching both keys
            // counts once, in FileDesc order - identical answers to the
            // pre-index linear drain (`try_match_linear`, kept below as
            // the test oracle). An exact candidate the head DENIED does
            // not fall through to here: a case-folded name is weaker
            // evidence than the exact one the content just refused, so
            // the content tiers own the slot from that point.
            //
            // `try_match_linear` in live/matchref.rs mirrors this whole
            // tier; the differential tests hold the two to the same
            // answers, `confirmed` included.
            let cands: Vec<usize> = if !exact.is_empty() {
                exact
            } else {
                let (mut i, mut j) = (0usize, 0usize);
                let mut first = None;
                while i < folded.len() || j < sanit.len() {
                    let fi;
                    if i < folded.len() && (j >= sanit.len() || folded[i] <= sanit[j]) {
                        fi = folded[i];
                        i += 1;
                        if j < sanit.len() && sanit[j] == fi {
                            j += 1;
                        }
                    } else {
                        fi = sanit[j];
                        j += 1;
                    }
                    if claimed[fi].is_none() {
                        if first.is_none() {
                            first = Some(fi);
                        } else {
                            name_ambiguous = true;
                            first = None;
                            break;
                        }
                    }
                }
                first.into_iter().collect()
            };
            let want = self.head_want();
            let hit = arbitrate_by_head(&cands, active, want, head_key);
            if hit.is_none() && !cands.is_empty() {
                // Confirmed-plural, denied, or waiting on the head: all
                // three are "not yet", never "never" (see the fn note).
                name_ambiguous = true;
                // The tentative nominee, taken below only if the
                // content tiers find nothing better. With NO head yet
                // the first candidate is taken however many there are -
                // that is the pre-nomination answer, and it is safe
                // again because the binding is tentative: the head
                // completing re-judges it (`rejudge_binding`) and moves
                // it to the descriptor the content names, so FileDesc
                // order no longer DECIDES anything (W4-02B). With a head
                // that denied every candidate there is nothing to
                // re-judge, so a sole candidate is the only one worth
                // verifying against.
                nominee = if head_key.is_none() {
                    cands.first().copied()
                } else if cands.len() == 1 {
                    Some(cands[0])
                } else {
                    None
                };
            }
            if let Some((fi, sure)) = hit {
                if sure {
                    claimed[fi] = Some(slot);
                }
                self.file = Some(fi);
                self.confirmed = sure;
                self.head_nominated = false;
                self.blocks = vec![BlockState::Pending; active.file(fi).blocks.len()];
                return true;
            }
        }
        // md5-16k fallback (obfuscated names). UNIQUE among the unclaimed
        // descriptors, same rule as the approximate name tier above: two
        // same-length files sharing an identical first 16 KiB (zero-filled
        // heads - padded VOBs, disk images) both match both descriptors,
        // and taking the first hit made WHICH slot claimed which a
        // worker-thread race (matrix finding F1, measured 29 Aug 2026:
        // crossed ~1 run in 5 on a loaded box; at r=10 the crossed pairing
        // reads every differing block as damage and FAILS an intact post).
        // Declined ambiguity resolves later, and WHICH tier resolves it
        // is worth naming, because `try_match_whole`'s `cands.len() < 2`
        // early return leans on this one. A twin's claim makes the
        // remaining candidate unique on retry - and the retry that
        // matters is the FINISH-time one, not the in-stream pass a
        // reader assumes: `finish_slot_from` runs this tier again, so
        // the twin that settles SECOND finds a sole unclaimed candidate
        // and is claimed HERE, never reaching the twin tier at all. What
        // reaches `try_match_whole` is only the case where two or more
        // are still unclaimed, and it settles those by whole-file MD5
        // and then by per-block evidence.
        //
        // Since M4-103 that second twin arrives as a NOMINATION, and it
        // holds on silence rather than on the head: a slot that declined
        // in-stream carries no block verdicts, so there is nothing for
        // `head_nomination_holds` to contradict it with, which is the
        // answer the pre-nomination code gave too.
        // `damaged_identical_head_twins_land_in_either_settle_order`
        // pins the hand-off from both ends.
        let want = self.head_want();
        let mut head_ambiguous = false;
        if want > 0
            && self
                .head
                .as_ref()
                .is_some_and(|h| h.buf.len() == want && h.complete())
        {
            let head_md5: [u8; 16] = Md5::digest(&self.head.as_ref().unwrap().buf).into();
            let mut hit: Option<usize> = None;
            // A descriptor this head DOES name, held by ANOTHER slot
            // (F9, 1 Sep 2026). Recorded because the skip is otherwise
            // invisible - `hit` stays `None` and `head_ambiguous` stays
            // false, so the latch below fired as though the head had
            // matched nothing at all. Since M4-103 the hold may be a
            // revocable NOMINATION that `settle_binding` hands back at
            // finish, so "taken now" is not "never mine": an uncovered
            // payload whose head completed first latched the REAL
            // member, which was then refused for the rest of the run
            // (`on_data`'s early-out, and `finish_slot_from` skipping
            // the whole last-chance ladder) and left unclaimed after the
            // impostor's claim came back - a byte-perfect file on disk
            // priced WHOLLY MISSING against parity. The claimed test has
            // to run AFTER the content filter, or a descriptor that only
            // shares this slot's declared length would suppress the
            // latch too.
            let mut claimed_rival = false;
            for (fi, f) in active.files() {
                if f.length.min(HEAD_LEN as u64) != want as u64 {
                    continue;
                }
                if f.md5_16k != head_md5 {
                    continue;
                }
                if claimed[fi].is_some() {
                    claimed_rival = true;
                    continue;
                }
                match hit {
                    None => hit = Some(fi),
                    // W4-15: ONE FILE DESCRIBED BY TWO RECOVERY SETS IS
                    // NOT TWO FILES. The rivalry this tier declines on is
                    // two DIFFERENT files that happen to share a 16 KiB
                    // head - zero-filled heads, padded VOBs - and what
                    // makes them different is the whole-file MD5. Two
                    // descriptors agreeing on the length AND that MD5
                    // describe the same bytes, which is the ordinary
                    // shape of a post carrying two overlapping sets over
                    // one member. Declining there cost the whole row:
                    // with both sets live the payload matched two entries
                    // and neither, the slot stayed unclaimed, and a
                    // 4-block loss on an intact-but-damaged file was
                    // priced WHOLLY MISSING - `try_match_whole` cannot
                    // rescue it either, because a damaged file matches
                    // no candidate's whole-file MD5 at all.
                    //
                    // Safe where claiming a real twin by elimination is
                    // not (see `try_match_whole`'s note): the objection
                    // there is that settle could publish this slot's
                    // bytes under the OTHER file's name, and here the
                    // other descriptor declares the same length and the
                    // same content hash, so there is no other file to be
                    // wrong about.
                    Some(h) if active.file(h).length == f.length && active.file(h).md5 == f.md5 => {
                        continue;
                    }
                    Some(_) => {
                        head_ambiguous = true;
                        hit = None;
                        break;
                    }
                }
            }
            if let Some(fi) = hit {
                // A 16 KiB HEAD IS EVIDENCE, NOT AUTHORITY (M4-103,
                // 31 Aug 2026). This tier used to CLAIM outright here,
                // and nothing after that ever re-read the file, so an
                // uncovered payload took a member's descriptor the
                // moment it shared that member's first 16 KiB - the
                // ordinary shape of a zero-filled head, which is the
                // very thing the plural decline above names. Measured:
                // the payload was renamed onto the member, verified AS
                // the member, and failed the job unrepairable.
                //
                // So the head NOMINATES. The claim is still TAKEN here,
                // which is what keeps every exclusion this tier depends
                // on working (a twin's claim making the remaining
                // candidate unique on retry, W4-15's duplicate-set arm,
                // the `unmatchable` latch) and what keeps the hot path
                // exactly as fast as it was - but it is REVOCABLE:
                // `settle_binding` re-judges it at finish and hands the
                // claim back when the bytes deny it.
                //
                // EXCEPT WHERE THE HEAD IS THE WHOLE FILE. For a
                // descriptor of 16 KiB or less `md5_16k` IS its
                // whole-file MD5 (short files are not zero-padded, see
                // `par2::md5_16k_of_head`) and the filter above has
                // already required the slot to declare exactly that
                // length, so it is the strongest evidence the file
                // admits and it finalizes.
                let whole_file = active.file(fi).length <= HEAD_LEN as u64;
                claimed[fi] = Some(slot);
                self.file = Some(fi);
                self.confirmed = whole_file;
                self.head_nominated = !whole_file;
                self.blocks = vec![BlockState::Pending; active.file(fi).blocks.len()];
                return true;
            }
            // Head is complete and matched nothing: if the name also failed,
            // this slot will never match (nfo/sfv/sample files). NOT when
            // EITHER tier declined on ambiguity - those candidates are real,
            // and a later claim by the twin slot makes the match unique.
            // Latching here froze the slot forever and downgraded a
            // patchable file to wholly-missing (found by the 14 Aug sweep).
            // NOR when the head named a descriptor another slot is merely
            // HOLDING (`claimed_rival`): "matched nothing" is false there,
            // and since M4-103 that hold can be handed back.
            if self.name.is_some() && !name_ambiguous && !head_ambiguous && !claimed_rival {
                self.unmatchable = Some(active.adopted_gen);
            }
        }
        // Nothing the content vouches for. Bind the name's sole nominee
        // TENTATIVELY so the slot keeps verifying in-stream, and let the
        // blocks say whether the name told the truth.
        if tentative
            && let Some(fi) = nominee
            && claimed[fi].is_none()
        {
            self.file = Some(fi);
            self.confirmed = false;
            self.head_nominated = false;
            self.blocks = vec![BlockState::Pending; active.file(fi).blocks.len()];
            return true;
        }
        false
    }

    /// Drop a tentative binding and everything measured under it,
    /// returning the (ok, bad, partial bytes) it discards.
    ///
    /// The block states, the live counts and the watermark prefix were
    /// all judged against a descriptor this slot turns out not to be, so
    /// none of them means anything now. The PARTIALS have to go with
    /// them and not merely be forgotten: they are keyed by BLOCK INDEX,
    /// and the next descriptor this slot binds has its own block size,
    /// so a surviving entry would be handed to a block it holds no bytes
    /// of. The caller winds the returned figures out of the GLOBAL
    /// counters too - the live gauge would otherwise keep the phantom
    /// damage a lying name produced, and the partials budget would hold
    /// headroom for memory that is gone. Idempotent: a second call
    /// discards nothing.
    pub(super) fn unbind(&mut self) -> (u64, u64, usize) {
        self.file = None;
        self.confirmed = false;
        self.head_nominated = false;
        self.blocks = Vec::new();
        // And SAY that they went, to the one reader that cannot see it:
        // a decode thread hashing this slot's bytes outside the lock
        // snapshotted `bind_gen` beside the block indices it claimed,
        // and re-takes the lock to record verdicts that are now about a
        // descriptor this slot does not hold. Moving the generation is
        // what makes it drop them instead of indexing the next
        // binding's grid with the last one's indices (see the field
        // doc). `wrapping_add` because a counter that can only be
        // compared for equality has nothing to overflow into.
        self.bind_gen = self.bind_gen.wrapping_add(1);
        self.ok_prefix = 0;
        // §94 B per-range: the Ok bitmap described THAT grid, and a
        // chase reader may still be holding the same `Arc`. Clear it
        // before dropping it, so what that reader sees is "nothing
        // vouched" (which parks it) and never a bit about a block the
        // next descriptor numbers differently. The next `gate_publish`
        // arms a fresh map, which re-clears this one as well.
        if let Some(v) = self.vouch.take() {
            v.clear();
        }
        // The latch is a statement about a DESCRIPTOR's entries, so it
        // goes with the binding it was made against (M4-69). Carrying it
        // to the next descriptor would cost a whole-file MD5 the honest
        // set beside it never asked for; it could never make a wrong
        // verdict, since the MD5 comparison is what gates the
        // escalation, only a wasted read.
        self.ifsc_self_contradicted = false;
        // Block INDICES of a grid that is gone (F10), for the same
        // reason the partials go: the next descriptor has its own block
        // size, so a surviving entry would name a block it says nothing
        // about.
        self.readback_forced.clear();
        self.partials.clear();
        (
            std::mem::take(&mut self.live_ok),
            std::mem::take(&mut self.live_bad),
            std::mem::take(&mut self.partial_bytes),
        )
    }
}
