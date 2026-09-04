//! Where each slot's file will actually land, decided BEFORE the first
//! rename of the settle publish pass.
//!
//! Split out of `settle.rs` (TODO 106 size gate); the whole argument for
//! the pass is on [`plan_publish_names`] itself.

use super::settle::{current_leaf, filedesc_name_is_better, set_name_loses_to_held};
use super::*;
use tracing::{info, warn};

/// Will `sidx` take the set's spelling and then GIVE IT BACK - the
/// M4-86 / GH #63 deferral - and if so, under what name does it come to
/// rest?
///
/// ONE DOOR FOR TWO ASKERS, and that is the whole point of it being a
/// function. `settle_slots` asks it to decide the rename;
/// [`plan_publish_names`] asks it BEFORE that, because a slot that
/// defers is not a stayer and the plan is built out of that
/// distinction. Written out twice these would drift, and the planner
/// disagreeing with the rename is exactly the defect this exists to
/// close - see the deferral paragraph on [`plan_publish_names`].
///
/// The two cheap tests come first so the ordinary post pays one
/// `contains` over a short name plus a bool load, never the
/// `slot_path` lookup behind them.
///
/// The answer is read off the leaf the file carries AT THE MOMENT OF
/// ASKING, so the planner's answer and the rename's can differ when the
/// planner itself has moved the slot aside in between: `Name.mkv`
/// becomes `000-Name.mkv`, which `nzbkit::release::stem_is_a_name`
/// still calls a name, so the deferral survives the detour and comes
/// back to the disambiguated spelling. That is the plan working - the
/// aside is only taken when some set member's own descriptor names that
/// file - and it is a coupling rather than an accident, so an aside
/// convention that stopped reading as a name would silently turn these
/// slots into stayers again.
pub(super) fn deferred_name(
    slot: &crate::unpack::FileSlot,
    par2_name: Option<&str>,
    extractor: &Arc<nzbkit::extract::Extractor>,
    sidx: usize,
) -> Option<String> {
    par2_name
        .filter(|p| p.contains(char::REPLACEMENT_CHARACTER) || !filedesc_name_is_better(slot, p))
        .and_then(|p| current_leaf(extractor, sidx).filter(|h| set_name_loses_to_held(slot, p, h)))
}

/// Decide, before a single file moves, which names the publish pass may
/// claim - and break any rename CYCLE among them.
///
/// Three rules, and the first is why this cannot stay where it was (a
/// seed of every live slot path, taken before settling):
///
/// * A slot only OWNS the name it sits under if it is going to stay
///   there. Seeding a name its own slot is about to vacate pushed the
///   name's rightful owner onto a `{slot:03}-` prefix for a collision
///   that never actually happens.
/// * A FileDesc name OUTRANKS a posted one. A slot keeping its posted
///   name yields it to the set member that name belongs to - see the
///   note at that loop for what a member pushed off its own name costs.
/// * Two slots publishing into each other's current names are a rename
///   CYCLE, and `fs::rename` REPLACES - so whichever publishes first
///   destroys the other's bytes. Any mover whose current name is another
///   slot's target is moved aside to a temporary name here, which makes
///   every target free by the time the publish pass reaches it.
///
/// The shape that needs all three is crossed yEnc names over an intact pair:
/// the matcher now resolves the identities by content (see
/// `nzbkit::live::SlotState::try_match`), and this is what lets the two
/// files actually land under them. It costs nothing on the ordinary post
/// - obfuscated hash names are nobody's target, so both lists are empty
/// and this is one pass over the slots.
///
/// # A slot moves in TWO ways, and only one of them is a `moves` entry
///
/// Claim `publishplan-model-vs-deferred-rename` (31 Aug 2026). Rule 1
/// says a slot owns the name it sits under only if it is going to stay
/// there, and `17449b055` made that FALSE for a class this function was
/// classifying as stayers. A GH #63 slot - the post's subject is an
/// honest name, the set's FileDesc a hash - used to refuse the rename
/// and never move. It now DEFERS instead: it takes the set's spelling
/// so the disk-side repair can find its own member, and the honest name
/// comes back through `deferred_renames` in `tail::report_extraction`.
/// So it vacates its name and returns to it, and its TRANSIENT target
/// is a name this plan has to keep free - while `moves` skips it by
/// construction, since `moves` is built out of the very predicate that
/// used to refuse. [`deferred_name`] is that second list, asked through
/// the same door `settle_slots` decides the rename with.
///
/// MEASURED on an INTACT crossed pair before the second list existed:
/// slot A posted `Real.Feature.2021.1080p-GRP.mkv` with a hash
/// FileDesc, slot B the exact inverse, so A's deferred target is B's
/// current name and B's target is A's.
///
/// ```text
/// renamed Real.Feature…mkv → 000-Real.Feature…mkv (the recovery set names that file)
/// renamed 000-Real.Feature…mkv → KpZ7mQx4TvB9nR2sLdFq.mkv (replaced the previous copy)
/// renamed KpZ7mQx4TvB9nR2sLdFq.mkv → Real.Feature…mkv
/// verified 2 file(s): 2000 blocks in-stream, 0 by read-back, 0 bad
/// ```
///
/// Both files verified every block, rc=0, and ONE file was on disk at
/// the end carrying A's bytes under B's name - B's payload gone, on a
/// post that was never damaged. `replaced the previous copy` is the
/// whole of the trace. B was a mover, so the seeding loop skipped it
/// and `PublishedNames` held neither its name nor its inode; A's claim
/// therefore read as a previous RUN's copy, which the strong tier is
/// entitled to replace. The cycle arm could not see it either, because
/// A was not in `moves`. Pinned by `e2e_norar::deferredcross`.
///
/// What does NOT change is the aside: a deferring slot whose own name
/// is somebody's target still steps aside under the `{slot:03}-`
/// convention rather than to a swap temp, and it must, because its
/// final name is read back off that leaf - see [`deferred_name`]. Only
/// MOVERS are swapped aside below, whose final name is their target.
///
/// AND A SLOT CAN BE BOTH, which is what decides the ORDER the two
/// lists are asked in - claim `publishplan-mover-that-also-defers`,
/// 31 Aug 2026. M4-86's own shape satisfies `filedesc_name_is_better`
/// AND defers, so with `moves` asked first it was sorted by the fact
/// that it leaves rather than by where it comes to rest, and the
/// paragraph above stopped being true of it: it got the swap temp, and
/// the swap temp is what [`deferred_name`] then read its return name
/// off. MEASURED intact at rc=0 with every block verified -
/// `_nzbfast-swap-0` beside the readable name. Deferral is asked first
/// now, so a slot that comes back is a deferrer whatever else is also
/// true of it. The argument is at the branch itself.
///
/// And the deferral targets are deliberately NOT in `wanted`, which is
/// the wider fix this row was expected to want and MEASURED not to -
/// the reasoning is at that binding, and the case that settled it is
/// pinned beside the two rows above.
pub(super) fn plan_publish_names(
    slots: &[Arc<FileSlot>],
    settled: &[(usize, Option<nzbkit::live::SlotReport>)],
    extractor: &Arc<nzbkit::extract::Extractor>,
    out_dir: &Path,
    published_names: &mut crate::unpack::PublishedNames,
) {
    // slot → the out_dir-relative name it will publish under, for the
    // slots that will actually move. Mapped and chased slots are excluded
    // for the same reason the publish pass excludes them: no finished
    // file on disk to rename. A CHASED slot is excluded from `defers`
    // for a second reason of its own: its deferred rename is its ONLY
    // rename, so it never occupies the set's spelling at all and has no
    // transient target to keep free.
    let mut moves: Vec<(usize, String)> = Vec::new();
    // slot → the name it holds only while the repair runs, for the
    // slots that move and then COME BACK. See the deferral section on
    // this function. These are targets for the CYCLE arm alone and not
    // for `wanted`: a file is about to be moved onto them, so nothing
    // else may be moved onto them first, but they are borrowed rather
    // than claimed - the reasoning, and the measurement it rests on, is
    // at `wanted` just below.
    //
    // TWO ENTRIES OF THIS LIST CAN NEVER CROSS, and it is worth knowing
    // because the crossing that cost a payload above was a mover against
    // a deferrer and the obvious next question is the pair of them -
    // claim `publishplan-two-deferrers-crossing`. Write L for a
    // deferrer's leaf and P for the name its set gives it.
    // `settle::set_name_loses_to_held` is what puts a slot here and both
    // its arms demand `stem_is_a_name(L)`; arm 1 (M4-86) additionally
    // demands that P carry U+FFFD and L not, arm 2 (GH #63) that P not
    // be a name. Crossing is D1.P = D2.L and D2.P = D1.L: arm 2 for D1
    // needs D1.P unreadable while D2.L is a name, and arm 1 needs D1.P
    // to carry U+FFFD while arm 1 for D2 forbids exactly that of D2.L.
    // Neither arm survives, so the shape does not exist. The joints in
    // that argument are the three transforms between the predicates'
    // view of a name and this list's - `sanitize_out_name`, the case
    // fold in `PublishedNames::key_of`, and the directory prefix
    // `out_name_of` adds to a tree-preserved slot.
    //
    // What the question was really about is the REPAIR WINDOW it
    // implies, and that needs no cross: an occupant on the transient
    // target pushes a member onto `{slot:03}-` just as well. MEASURED
    // for TWO members at once - `e2e_norar::deferredcross::
    // two_deferring_members_both_repair_with_neither_at_the_name_the_set_knows`
    // - and it generalises: 366 blocks rebuilt straight into the output
    // with both members sitting at `000-`/`001-` forms of the set's own
    // spelling, nothing adopted and nothing recreated. Repair reaches a
    // member through its SLOT, which is the same answer the one-deferrer
    // row at `wanted` below records.
    let mut defers: Vec<(usize, String)> = Vec::new();
    for (sidx, r) in settled {
        let (sidx, Some(r)) = (*sidx, r.as_ref()) else {
            continue;
        };
        if extractor.is_mapped(sidx) || extractor.is_chased(sidx) {
            continue;
        }
        let (Some(pname), Some(path)) = (r.par2_name.as_ref(), extractor.slot_path(sidx)) else {
            continue;
        };
        let target = nzbkit::disk::sanitize_out_name(pname);
        // Already sitting on it: neither a move nor a deferral, whichever
        // rule would otherwise have claimed the slot.
        if nzbkit::disk::out_name_of(out_dir, &path) == target {
            continue;
        }
        // DEFERRAL IS ASKED FIRST, and the order is the whole rule:
        // a slot can satisfy BOTH predicates, and what tells the two
        // lists apart is where the slot COMES TO REST. A mover's final
        // name is its target; a deferrer's is its LEAF. So a slot that
        // gives the name back belongs in `defers` however loudly
        // `filedesc_name_is_better` also says yes about it - claim
        // `publishplan-mover-that-also-defers`, and it is M4-86's own
        // shape rather than a corner: a mojibake FileDesc still reads
        // as a NAME to `nzbkit::release::stem_is_a_name`, so
        // `filedesc_name_is_better` is true, AND `lossy_name_loses_to`
        // fires, so `settle_slots` defers it back to the readable leaf.
        // With `moves` asked first that slot was skipped by the seeding
        // loop and swapped to `.nzbfast-swap-<n>` by the cycle arm
        // below - and the swap temp is what `deferred_name` then reads
        // the return name off. MEASURED on the pre-fix tree, intact,
        // rc=0, every block verified: `_nzbfast-swap-0 (220000 bytes)`
        // beside the readable name, a payload come to rest under this
        // function's own build artefact (`sanitize_out_name` takes the
        // leading dot off, so it is not even hidden). Pinned by
        // `e2e_norar::deferredcross::a_slot_that_moves_and_comes_back_is_never_parked_on_a_swap_temp`.
        //
        // Nothing else moves: a slot that satisfies only one of the two
        // predicates is sorted exactly as before, which is what the
        // control rows either side of that pin are for.
        if deferred_name(&slots[sidx], Some(pname), extractor, sidx).is_some() {
            defers.push((sidx, target));
        } else if filedesc_name_is_better(&slots[sidx], pname) {
            moves.push((sidx, target));
        }
    }
    // MOVERS ONLY, and the deferral targets are deliberately NOT in
    // here. Widening it was built first, on the reading that an occupant
    // left sitting on a name the set is about to address a member by is
    // W4-18's loss below; MEASURED, that is not what happens - repair
    // reaches a member through its SLOT, and with the deferring slot
    // pushed onto a `{slot:03}-` name by the occupant it still rebuilt
    // 358 blocks straight into the output with the occupant untouched
    // (`a_borrowed_transient_target_does_not_evict_the_occupant_sitting_on_it`,
    // which pins it). So the
    // widening bought no payload and cost the occupant its name
    // permanently, for a name the deferring slot only borrows.
    let wanted: std::collections::HashSet<String> = moves
        .iter()
        .map(|(_, t)| published_names.key_of(t))
        .collect();
    // Seeded from the live slot paths: a slot that simply KEEPS its
    // posted name owns that name, so another slot's verified name is
    // pushed off it instead of renaming over it. Both payloads then
    // survive under two names, which is the whole point - one of them
    // wearing a `{slot:03}-` prefix beats one of them gone.
    //
    // EXCEPT against a FileDesc name, which outranks a posted one, and
    // that exception is what makes the pair survive rather than merely
    // both exist. A set member pushed off its own descriptor's name is
    // not just oddly spelled: every later pass addresses set members BY
    // that name - the duplicate-FileDesc rescue, and repair itself - so
    // they find the OTHER file at the canonical path, reject it, and
    // repair then RECREATES the member straight over it. Measured on
    // W4-18 (30 Aug 2026): the uncovered payload posted honestly as
    // `Copy.One.bin` kept the name, the set's own verified copy landed
    // as `001-Copy.One.bin`, and repair rebuilt `Copy.One.bin` on top of
    // the uncovered file, which then existed nowhere. So the uncovered
    // occupant is the one that steps aside, under the same
    // `{slot:03}-` convention.
    for sidx in 0..slots.len() {
        if moves.iter().any(|(m, _)| *m == sidx) {
            continue;
        }
        let Some(p) = extractor.slot_path(sidx) else {
            continue;
        };
        // The out_dir-RELATIVE name, matching what a publish claims: a
        // tree-preserved slot owns its whole relative path.
        let here = nzbkit::disk::out_name_of(out_dir, &p);
        if !wanted.contains(&published_names.key_of(&here))
            || extractor.is_mapped(sidx)
            || extractor.is_chased(sidx)
        {
            published_names.seed(sidx, &here);
            continue;
        }
        // CAPPED, and through the one door rather than a bare
        // `format!`: `here` is the name the file already wears on disk,
        // so a long posted name has it sitting at EXACTLY the 255-byte
        // component cap - capping is what produced it - and a raw
        // `{sidx:03}-` prefix would compose a 259-byte component
        // `renameat` refuses with `ENAMETOOLONG`. The `Err` arm below
        // then seeds `here` back and the set member publishes
        // disambiguated, which is byte for byte the pre-fix W4-18 loss
        // the note above records. See
        // `nzbkit::disk::disambiguated_out_name` for why the cap goes on
        // the COMPOSED name here and not at the write, and note it is
        // the plain `format!` byte for byte for any name inside both
        // caps, so no ordinary post moves.
        let aside = nzbkit::disk::disambiguated_out_name(&here, sidx, 0);
        // Bound on the destination side too - see
        // `nzbkit::disk::rename_out_under` for the ancestor-swap half.
        match nzbkit::disk::rename_out_under(out_dir, &aside, &p) {
            Ok(t) => {
                info!(
                    target: "extract",
                    "renamed {here} → {aside} (the recovery set names that file)"
                );
                extractor.note_slot_renamed(sidx, t);
                published_names.seed(sidx, &aside);
            }
            Err(e) => {
                warn!(
                    target: "extract",
                    "could not move {here} aside for the recovery set's own \
                     {here}: {e} - the set member will publish under a \
                     disambiguated name instead"
                );
                published_names.seed(sidx, &here);
            }
        }
    }
    // EVERY COLLISION THIS FUNCTION CAN SEE, and where each is answered -
    // the question "has the cycle analysis finished?" reassembled in one
    // place, because the five answers were written at five sites over
    // three lanes. A collision is one slot's LEAF being another slot's
    // TARGET; the rows are the kind of slot whose leaf it is.
    //
    //   MOVER leaf vs MOVER target     -> swapped aside HERE. The
    //     original crossed-yEnc pair; a swap temp is safe because a
    //     mover's final name is its target.
    //   MOVER leaf vs DEFERRER target  -> swapped aside HERE too, which
    //     is why the loop below chains `defers`. Claim
    //     `publishplan-model-vs-deferred-rename`; before it, this was
    //     the crossed pair that lost a payload at rc=0.
    //   DEFERRER leaf vs MOVER target  -> the `{slot:03}-` ASIDE above,
    //     never a swap temp, because a deferrer comes back to its leaf
    //     and the aside still reads as a name. Claim
    //     `publishplan-mover-that-also-defers` is what made this reach
    //     the both-case as well as the pure one.
    //   DEFERRER leaf vs DEFERRER target -> CANNOT HAPPEN. Proof at the
    //     `defers` binding above; claim
    //     `publishplan-two-deferrers-crossing`.
    //   STAYER leaf vs MOVER target    -> the same aside above (W4-18).
    //   STAYER leaf vs DEFERRER target -> DELIBERATELY NOTHING. The
    //     occupant keeps its name; the reasoning and the measurement are
    //     at `wanted`.
    //
    // A new class of slot means a new ROW here, not just a new branch.
    //
    // Only MOVERS are swapped here, and the swap is safe for them
    // precisely because their final name is their target rather than
    // their leaf. The other side of the question is both lists: a mover
    // sitting on a DEFERRER's transient target is the crossed pair that
    // lost a payload above, and it is not a mover-versus-mover cycle at
    // all - the deferrer takes the name and gives it back, so nothing
    // ever wanted the mover's leaf. It still has to move out of the way
    // first, and `fs::rename` replacing is why.
    for (sidx, _) in &moves {
        let Some(path) = extractor.slot_path(*sidx) else {
            continue;
        };
        let here = published_names.key_of(&nzbkit::disk::out_name_of(out_dir, &path));
        if !moves
            .iter()
            .chain(defers.iter())
            .any(|(o, t)| o != sidx && published_names.key_of(t) == here)
        {
            continue;
        }
        let tmp = out_dir.join(format!(".nzbfast-swap-{sidx}"));
        match std::fs::rename(&path, &tmp) {
            Ok(()) => extractor.note_slot_renamed(*sidx, tmp),
            Err(e) => warn!(
                target: "extract",
                "could not move {} aside for a name swap: {e} - the two files \
                 will publish under disambiguated names instead",
                path.display()
            ),
        }
    }
}
