//! X5-24: charging a wholly missing file to the one recovery set
//! nothing claimed, under GLOBAL UNIQUENESS.
//!
//! # The shape
//!
//! A fully obfuscated post carrying one recovery set per file. Two
//! payloads arrive and claim their sets; the third's every article is
//! refused, so it delivers ZERO bytes. With zero bytes there is no
//! content claim to make - the md5-16k tier has no head to hash and
//! `nzbkit::par2repair::adopt` wants `len > 0` on both sides - so its
//! set matches nothing, a sibling set did match, and the post names
//! nothing usefully. The stray-release guard beside the damage loop
//! then reads the job's OWN set as a different release's and never
//! spends its parity, on a set that may be carrying 100% redundancy
//! over a file it could rebuild whole. The diagnosis is not merely
//! unhelpful, it is WRONG about whose file it is.
//!
//! [`super::emptydesc::names_offered_by_the_post`] is the census that
//! rescues the NAMED version of this (a post that offers a file and
//! loses it whole), and its own STATED LIMIT is this case: an
//! obfuscated post answers `false` there, so the set is skipped exactly
//! as before. That note also records size-banding an unclaimed slot
//! against a FileDesc length as CONSIDERED AND LEFT OUT, because the
//! answer CHARGES a whole set's content to damage and a coincidence of
//! size would send a repair shopping for a stray release's parity.
//! That objection is what the uniqueness rule below answers, and it is
//! why this is a narrow decidability test rather than a size match.
//!
//! # The rule, and it is a product decision rather than a heuristic
//!
//! Rebuild ONLY where the assignment is decidable from the post alone:
//! exactly one leftover set, naming exactly one still-missing file;
//! exactly one file this post lost WHOLE; a declared length that fits
//! that loss; and no second descriptor anywhere that fits it too.
//! Otherwise DECLINE - and say honestly which set was declined, what it
//! could have rebuilt, and why it was not attempted. Never the
//! foreign-release verdict about a set that may be the job's own.
//!
//! # Why every order gives the same answer
//!
//! Each clause is a COUNT or a uniqueness test. There is no
//! first-match tie-break anywhere: an index is read out of a list only
//! after that list has been proved to hold exactly one element, so set
//! order (which follows packet arrival) and NZB file order cannot move
//! the result. The e2e fixture drives the post forwards and fully
//! reversed and asserts the same rebuild.
//!
//! # THE STATED LIMIT, which is the whole of what uniqueness buys
//!
//! There is no evidence anywhere that says whose set a leftover set is.
//! Every clause above is a DECIDABILITY test, never a proof of
//! ownership: where a post has lost exactly one file whole and carries
//! exactly one leftover set of about that size, this charges the loss
//! to that set whether the set is the post's own or a stray the poster
//! left behind. The bad case costs the stray's recovery volumes off the
//! wire and a rebuilt file of another release in the output directory,
//! and the job still fails on the real loss. It needs a size
//! coincidence inside the band below to happen at all, and the four
//! counting clauses to hold at the same time. That trade was taken
//! deliberately (30 Aug 2026), with the alternative in front of it: the
//! version that never assigns is what shipped until now, and it fails a
//! job whose own parity would have rebuilt it, while telling the user
//! the file belongs to somebody else. The lever if the trade ever needs
//! narrowing is the BAND, not the counts - yEnc encoding only ever
//! grows a file, so a posted count below the declared length is already
//! a poster's arithmetic rather than a fit.
//!
//! # What this deliberately cannot do
//!
//! It proves nothing about the bytes. The PROOF is the repair's own:
//! the set rebuilds the file from its parity and checks the whole-file
//! MD5 the FileDesc declares, exactly as it does for a named file the
//! post offered and lost. What this decides is only WHICH descriptor
//! the loss is, and it decides it by refusing every case where more
//! than one answer is available.

use crate::*;
use std::collections::HashSet;
use std::sync::atomic::Ordering;
use tracing::{info, warn};

/// The one assignment the post admits.
pub(super) struct Assignment {
    /// Index into `sets`, the way `LiveVerifier::sets` is indexed.
    set: usize,
    /// The FileDesc name that stands for the loss.
    name: String,
    /// The slot that lost every article, for the log.
    slot: usize,
    /// That slot's NZB-declared (yEnc-encoded) byte count, for the log:
    /// it and the descriptor's own length are the whole of the evidence
    /// the size clause read, so the line prints both.
    posted: u64,
}

/// Is `posted` (a yEnc-ENCODED NZB byte count, and explicitly
/// approximate) the size of a file `length` bytes long?
///
/// The same 90..120% band `super::settle::reconcile_obfuscated_aliases`
/// uses for the same "which file was this really" question, and copied
/// rather than shared because the two answer it at different moments
/// and under different evidence: there the descriptor has already been
/// PROVED by a repair and the pairing only SPARES a slot, here nothing
/// is proved yet and the answer CHARGES a set's content to damage. A
/// sizeless NZB fits nothing, which is what stops a post that declares
/// no bytes from assigning anything at all.
fn size_fits(posted: u64, length: u64) -> bool {
    posted > 0
        && length > 0
        && posted.saturating_mul(100) >= length.saturating_mul(90)
        && posted.saturating_mul(100) <= length.saturating_mul(120)
}

/// A file this post OFFERED and delivered nothing of.
///
/// Arrived nothing at all (the strictest of the two shapes
/// `reconcile_obfuscated_aliases` allows, and the only one where the
/// slot can carry no content claim whatever), claimed no set's
/// descriptor, is not recovery data by either route, and was not
/// declined on purpose by the sample skip - a skipped file is absent
/// because the user asked for it to be, and rebuilding it from parity
/// is the exact traffic that setting exists to refuse.
fn lost_whole(slots: &[Arc<FileSlot>], verifier: &Arc<nzbkit::live::LiveVerifier>) -> Vec<usize> {
    slots
        .iter()
        .enumerate()
        .filter(|(i, s)| {
            s.total_segments > 0
                && s.missing.load(Ordering::Relaxed) == s.total_segments
                && !s.sample_skipped
                && !s.is_par2()
                && verifier.slot_set(*i).is_none()
        })
        .map(|(i, _)| i)
        .collect()
}

/// The set-and-file this post's one total loss must be, or the reason
/// no such answer exists. The `Err` is the tail of the decline
/// sentence, so it reads as the end of "...it could rebuild it, and was
/// not asked to - {reason}".
#[expect(clippy::too_many_arguments)]
fn assign(
    sets: &[Arc<nzbkit::par2::Par2Set>],
    set_has_claims: &[bool],
    missing_files: &[String],
    offered_names: &HashSet<String>,
    slots: &[Arc<FileSlot>],
    slot_file: &[usize],
    nzb: &Nzb,
    verifier: &Arc<nzbkit::live::LiveVerifier>,
) -> Result<Assignment, String> {
    let leftover: Vec<usize> = (0..sets.len()).filter(|&si| !set_has_claims[si]).collect();
    if leftover.len() != 1 {
        return Err(format!(
            "{} recovery sets in this post matched nothing, so which of them stands for a \
             file this post lost cannot be decided",
            leftover.len()
        ));
    }
    let si = leftover[0];
    // Its own still-missing descriptors, minus any the post NAMES: one
    // the post offered is charged by the census beside the guard and is
    // not this tier's business, and leaving it in would make a set with
    // one named loss and one unnamed one look undecidable when it is
    // not.
    let mine: Vec<&nzbkit::par2::Par2File> = sets[si]
        .files
        .iter()
        .filter(|f| {
            missing_files.iter().any(|n| n == &f.name)
                && !offered_names.contains(&nzbkit::disk::sanitize_out_name(&f.name).to_lowercase())
        })
        .collect();
    if mine.is_empty() {
        return Err(
            "every file it names was offered by this NZB, so there is no unnamed loss left \
             for it to stand for"
                .to_string(),
        );
    }
    if mine.len() > 1 {
        return Err(format!(
            "it names {} files this post neither delivered nor listed, so which of them a \
             loss would stand for cannot be decided",
            mine.len()
        ));
    }
    let f = mine[0];
    let lost = lost_whole(slots, verifier);
    if lost.is_empty() {
        return Err(
            "no file in this NZB is wholly missing, so nothing in this post is a candidate \
             for it"
                .to_string(),
        );
    }
    if lost.len() > 1 {
        return Err(format!(
            "{} files in this NZB are wholly missing, so which of them it stands for \
             cannot be decided",
            lost.len()
        ));
    }
    let slot = lost[0];
    // `.get()` twice rather than two index expressions: this runs on
    // poster-controlled shapes, and a settle pass is the last place a
    // panic may be introduced. Either miss means the post cannot say
    // how big the loss was, which is a decline and not a crash.
    let Some(posted) = slot_file
        .get(slot)
        .and_then(|fi| nzb.files.get(*fi))
        .map(|f| f.bytes())
    else {
        return Err("this NZB declares no size for the file it lost whole".to_string());
    };
    if !size_fits(posted, f.length) {
        return Err(format!(
            "the {} bytes it declares are not the size of the one file this post lost whole \
             ({posted} bytes posted)",
            f.length
        ));
    }
    // ...and nothing ELSE the post is missing may fit that loss either.
    // With one leftover set naming one file this is normally vacuous;
    // it is not vacuous when a CLAIMED set has a file of its own lost
    // whole, which is a second answer to the same question.
    let rivals = sets
        .iter()
        .flat_map(|s| s.files.iter())
        .filter(|g| {
            g.name != f.name
                && missing_files.iter().any(|n| n == &g.name)
                && size_fits(posted, g.length)
        })
        .count();
    if rivals > 0 {
        return Err(format!(
            "{rivals} other descriptor(s) in this post declare a size that fits the loss too, \
             so the assignment is not unique"
        ));
    }
    Ok(Assignment {
        set: si,
        name: f.name.clone(),
        slot,
        posted,
    })
}

/// A member this job OWNS - the charge loop below took it past the
/// stray-release guard and warned the user it is missing entirely - and
/// priced at ZERO blocks of damage.
///
/// Wave-4 rows W4-09 and M4-45, 30 Aug 2026. `length.div_ceil(block)` is
/// zero for exactly one shape, a zero-length FileDesc, and zero damage
/// means no repair is ever asked for and no verdict ever sees the
/// absence. Measured before this: a dirty output directory holding a
/// nonempty file at a zero-length member's path logged `already exists
/// and is not empty - left alone`, then `✘ ... - file missing entirely`,
/// and returned rc=0. The malformed half (length 0 with a digest no
/// empty file can hash to) reaches the same place by a different door.
///
/// Charging it a notional block instead was CONSIDERED AND REJECTED:
/// damage is what sizes the recovery fetch, so a phantom block sends the
/// set shopping for parity it does not need, and the repair it would
/// then run has literally no slices to rebuild - a zero-length file has
/// none. The absence is real and the price is honestly zero; what was
/// missing is that nothing carried the absence to the verdict. So the
/// name is carried out instead, and [`super::emptydesc`]'s finish-time
/// pass re-reads the directory once every tier and every repair has run.
pub(super) struct Unpriced {
    /// Index into `sets`, the way `LiveVerifier::sets` is indexed.
    pub set: usize,
    /// The FileDesc name, as the descriptor spells it.
    pub name: String,
}

/// W4-15's rule at the WHOLLY-MISSING door: every OTHER set that
/// describes this same file is charged for it too, in its own geometry.
///
/// The charge loop hands a name to the FIRST set naming it, and that
/// pick is an arrival race - `missing_file_names`' own note says the
/// sibling "is charged nothing at all" and leaves it there. Which set
/// OWNS a member is a race; which set can HEAL it is not, which is
/// exactly what [`nzbkit::live::LiveVerifier::slot_twin_damage`] says
/// one door over for a member that arrived DAMAGED. A set with no
/// damage gets no plan and is never repaired, so without this the
/// sibling's parity is never spent on a loss it could rebuild whole.
///
/// MEASURED 31 Aug 2026 - two sets over one obfuscated member, the
/// member lost whole, weak set (1 recovery block) charged: `native
/// repair: 20 block(s) damaged, only 1 recovery block(s) on disk`, and
/// `20 recovery block(s) needed ... carries only 1` - a sentence
/// that is false about the post, which carries 23 - while the strong
/// set's 22 slices lay on disk, already fetched. The identical bytes
/// with the strong set charged repaired and completed. See
/// `e2e_multiset::a_whole_loss_charged_to_the_weak_set_must_use_the_strong_parity`.
///
/// IDENTITY, NOT NAME ALONE, and both halves are load-bearing. The NAME
/// is what stops a double charge: two descriptors of one content under
/// DIFFERENT names are two entries in `missing_files`, each finding its
/// own owner, so cross-charging by content alone would charge every set
/// twice - which is precisely the defect `missing_file_names`' dedupe
/// was written to close (29 Aug 2026 sweep, M3), reintroduced from the
/// other side. The DIGESTS are what stop a guess: two sets naming one
/// file under different `(length, md5, md5_16k)` describe different
/// bytes, and charging a set's content on weaker evidence than identity
/// is the trade this module's own doc refuses - it is `slot_twin_damage`'s
/// own three-field test, spelled the same way. That door needs no name
/// clause because it charges a SLOT, of which there is exactly one; this
/// one iterates NAMES, so the name has to be part of the test.
fn charge_twin_sets(
    sets: &[Arc<nzbkit::par2::Par2Set>],
    owner: usize,
    f: &nzbkit::par2::Par2File,
    damage_by_set: &mut [usize],
) {
    for (tsi, set) in sets.iter().enumerate() {
        if tsi == owner {
            continue;
        }
        let Some(g) = set.files.iter().find(|g| {
            g.name == f.name && g.length == f.length && g.md5 == f.md5 && g.md5_16k == f.md5_16k
        }) else {
            continue;
        };
        // Its OWN geometry: two sets need not share a block size, and
        // what this one has to rebuild is its own slice count.
        damage_by_set[tsi] += g.length.div_ceil(set.block_size.max(1)) as usize;
    }
}

/// THE STRAY-RELEASE GUARD, written once. Is descriptor `f` a
/// DIFFERENT release's - part of a recovery set this post carries and
/// does not own?
///
/// Three doors ask it: the damage charge below, and the two landing
/// tiers in [`super::emptydesc`], whose own comments said the rule was
/// "copied from the damage loop beside the call site" and "the same
/// ownership and stray-set rules as the damage loop". It was copied,
/// twice - and a rule written three times is one that is wrong in three
/// places at once, which on 31 Aug 2026 it was.
///
/// THREE clauses, and there are three rather than four for a reason
/// worth reading before anybody adds the fourth back. The rule used to
/// ask, separately, whether the set the descriptor came from had
/// claimed anything of its own. That test is SUBSUMED by the third
/// clause below - a descriptor's own set describes it by construction,
/// so a set with claims that names it is that set itself whenever it
/// has any - and a guard that is sufficient beside another sufficient
/// one is a pair no mutation can falsify, which is CLAUDE.md's
/// FORTY-SIXTH entry. Measured rather than reasoned out: with both in
/// place, blanking the `set_has_claims[si]` test killed no test in this
/// module, which is how the redundancy was found at all.
///
/// Every clause that remains is load-bearing:
///
/// * NOTHING IN THE POST CLAIMED ANY SET AT ALL. With no sibling to
///   read a set against there is nothing to contradict the par-only
///   reading, and that reading has always been the right one for a
///   single-set post. This is what scopes the guard so it cannot fire
///   on one.
/// * THE POST OFFERS THE NAME. An NZB entry for the file is evidence
///   the packets cannot carry, and it is what tells the MIXTURE (a
///   per-file-set post with one file taken down whole) from the stray.
///   [`super::emptydesc::names_offered_by_the_post`] carries that
///   argument and its stated limits.
/// * A SET THAT DID CLAIM DESCRIBES THIS SAME FILE (31 Aug 2026).
///   `set_has_claims` is [`super::settle::sets_with_claims`], which
///   marks set N only where some slot's OWNING descriptor is N's - and
///   ownership is SINGULAR, [`nzbkit::live::LiveVerifier::slot_set`]
///   resolving to one `usize`. That is `slot_twin_damage`'s own stated
///   premise one door over: "a slot has exactly ONE owning descriptor,
///   and which set that is comes down to the in-stream bootstrap race".
///   So where two sets name the same files and a slot claims one of
///   them, the OTHER claims nothing, and before this clause existed the
///   guard read the job's own sibling as a foreign release and spent
///   none of its parity. Measured on origin/main 31 Aug 2026: two sets over one
///   arriving member and two lost whole, the set the race left
///   unclaimed named the losses first, and the job failed with that
///   set's blocks on disk - see
///   `e2e_multiset::a_sibling_set_the_race_left_unclaimed_is_not_a_stray_release`.
///
///   THE EVIDENCE IS STRONGER THAN THE UNIQUENESS this module's
///   residual tier settles for, not weaker, so it needs none of the
///   trade the header refuses: a set that claimed something describes
///   these very bytes, which says the post owns both sets rather than
///   guessing that it might. It is also the only clause that reaches a
///   FULLY OBFUSCATED post, where `offered_names` answers `false` by
///   construction and the clause above it can never help.
///
///   IDENTITY, NOT NAME ALONE, and it is [`charge_twin_sets`]'s test
///   spelled the same way ON PURPOSE. Two sets naming one file under
///   different `(length, md5, md5_16k)` describe different bytes, so a
///   name agreement alone would forgive a stray whose descriptor
///   happens to share a name with a member of the job's own. And the
///   two tests have to stay ONE test: forgiving a set here is what
///   sends the charge loop on to charge it and its twins, so a
///   descriptor forgiven under a looser rule than the twin charge uses
///   is one that gets charged with no twin to charge beside it.
pub(super) fn is_a_stray_release(
    sets: &[Arc<nzbkit::par2::Par2Set>],
    set_has_claims: &[bool],
    offered_names: &HashSet<String>,
    f: &nzbkit::par2::Par2File,
) -> bool {
    set_has_claims.iter().any(|&c| c)
        && !offered_names.contains(&nzbkit::disk::sanitize_out_name(&f.name).to_lowercase())
        && !sets.iter().enumerate().any(|(tsi, set)| {
            set_has_claims[tsi]
                && set.files.iter().any(|g| {
                    g.name == f.name
                        && g.length == f.length
                        && g.md5 == f.md5
                        && g.md5_16k == f.md5_16k
                })
        })
}

/// Charge every still-missing FileDesc to the set whose parity can heal
/// it, and warn about it. Returns the members it owned but could charge
/// NOTHING for - see [`Unpriced`].
///
/// Moved out of `settle_with_set` whole (`get/settle.rs` was at 2,982
/// of the size gate's 3,000-line ceiling on 30 Aug 2026) with the
/// residual tier folded in: the stray-release
/// guard's `continue` is now taken only where the assignment is NOT
/// decidable, and it says which set it declined and why.
#[expect(clippy::too_many_arguments)]
pub(super) fn charge_missing_files(
    missing_files: &[String],
    sets: &[Arc<nzbkit::par2::Par2Set>],
    set_has_claims: &[bool],
    offered_names: &HashSet<String>,
    slots: &[Arc<FileSlot>],
    slot_file: &[usize],
    nzb: &Nzb,
    verifier: &Arc<nzbkit::live::LiveVerifier>,
    damage_by_set: &mut [usize],
) -> Vec<Unpriced> {
    let mut unpriced = Vec::new();
    // Computed ONCE, over the whole post, before anything is charged:
    // the answer is a property of the job and not of the descriptor
    // being looked at, and deriving it inside the loop would make it
    // depend on how far the loop had got.
    let residual = assign(
        sets,
        set_has_claims,
        missing_files,
        offered_names,
        slots,
        slot_file,
        nzb,
        verifier,
    );
    for name in missing_files {
        // First set naming it owns it. A name in two sets is a duplicate
        // posting, and `unclaimed_files` already withholds one some slot
        // claimed - what is left here really is absent, and one set
        // rebuilding it is enough.
        let Some((si, f)) = sets
            .iter()
            .enumerate()
            .find_map(|(si, set)| set.files.iter().find(|f| f.name == *name).map(|f| (si, f)))
        else {
            continue;
        };
        if is_a_stray_release(sets, set_has_claims, offered_names, f) {
            match &residual {
                Ok(a) if a.set == si && a.name == *name => {
                    info!(
                        target: "verify",
                        "recovery set {} is the only one nothing in this post claimed and \
                         {} is the only file this post lost whole ({} bytes posted against \
                         {} declared), so its parity is spent rebuilding it as {}",
                        &nzbkit::par2::hex16(&sets[si].recovery_set_id)[..8],
                        slots[a.slot].hint,
                        a.posted,
                        f.length,
                        f.name,
                    );
                }
                other => {
                    let why = match other {
                        Ok(a) => format!(
                            "the one assignment this post admits is {} rather than this",
                            a.name
                        ),
                        Err(e) => e.clone(),
                    };
                    info!(
                        target: "verify",
                        "recovery set {} matched nothing in this post and this NZB does not \
                         list {}; it could rebuild it, and was not asked to - {}",
                        &nzbkit::par2::hex16(&sets[si].recovery_set_id)[..8],
                        f.name,
                        why,
                    );
                    continue;
                }
            }
        }
        let blocks = f.length.div_ceil(sets[si].block_size.max(1)) as usize;
        damage_by_set[si] += blocks;
        charge_twin_sets(sets, si, f, damage_by_set);
        warn!(target: "verify", "✘ {} - file missing entirely", f.name);
        // Priced at nothing, so nothing downstream can see it. Carried
        // to the verdict instead - see [`Unpriced`].
        if blocks == 0 {
            unpriced.push(Unpriced {
                set: si,
                name: f.name.clone(),
            });
        }
    }
    unpriced
}

#[cfg(test)]
mod twin_charge_tests {
    use super::*;

    pub(super) fn file(name: &str, length: u64, md5: u8, md5_16k: u8) -> nzbkit::par2::Par2File {
        nzbkit::par2::Par2File {
            file_id: [0u8; 16],
            name: name.to_string(),
            length,
            md5: [md5; 16],
            md5_16k: [md5_16k; 16],
            blocks: Vec::new(),
        }
    }

    pub(super) fn set(
        block_size: u64,
        files: Vec<nzbkit::par2::Par2File>,
    ) -> Arc<nzbkit::par2::Par2Set> {
        Arc::new(nzbkit::par2::Par2Set {
            recovery_set_id: [0u8; 16],
            block_size,
            files,
            nonrecovery: Vec::new(),
            recovery_blocks_seen: 0,
        })
    }

    /// The row this exists for: two sets over one member, charged in each
    /// set's OWN geometry rather than the owner's.
    #[test]
    fn a_twin_set_is_charged_in_its_own_block_size() {
        let sets = vec![
            set(10_000, vec![file("Twin.bin", 200_000, 7, 9)]),
            set(20_000, vec![file("Twin.bin", 200_000, 7, 9)]),
        ];
        let mut damage = vec![0usize; 2];
        charge_twin_sets(&sets, 0, &sets[0].files[0], &mut damage);
        assert_eq!(
            damage,
            vec![0, 10],
            "the sibling must be charged its own 200000/20000 slices, and the owner \
             nothing (the caller has already charged it)"
        );
    }

    /// The DIGEST half. Two sets naming one file under different content
    /// describe different bytes, and charging a set's whole content on
    /// weaker evidence than identity is what this module's doc refuses.
    #[test]
    fn a_same_name_descriptor_with_a_different_digest_is_not_charged() {
        for (md5, md5_16k, why) in [
            (8u8, 9u8, "whole-file digest differs"),
            (7, 8, "16k digest differs"),
        ] {
            let sets = vec![
                set(10_000, vec![file("Twin.bin", 200_000, 7, 9)]),
                set(10_000, vec![file("Twin.bin", 200_000, md5, md5_16k)]),
            ];
            let mut damage = vec![0usize; 2];
            charge_twin_sets(&sets, 0, &sets[0].files[0], &mut damage);
            assert_eq!(damage, vec![0, 0], "charged on a guess: {why}");
        }
        // ...and a length that disagrees is the same answer.
        let sets = vec![
            set(10_000, vec![file("Twin.bin", 200_000, 7, 9)]),
            set(10_000, vec![file("Twin.bin", 400_000, 7, 9)]),
        ];
        let mut damage = vec![0usize; 2];
        charge_twin_sets(&sets, 0, &sets[0].files[0], &mut damage);
        assert_eq!(damage, vec![0, 0], "charged on a guess: length differs");
    }

    /// The NAME half, and it is what stops a DOUBLE charge rather than a
    /// wrong one. Two descriptors of one content under different names
    /// are two entries in `missing_files`; each finds its own owner, so a
    /// content-only rule charges both sets twice - the 29 Aug 2026 sweep
    /// M3 defect, reintroduced from the other side.
    #[test]
    fn a_differently_named_descriptor_of_the_same_content_is_not_charged() {
        let sets = vec![
            set(10_000, vec![file("Copy.One.bin", 200_000, 7, 9)]),
            set(10_000, vec![file("Copy.Two.bin", 200_000, 7, 9)]),
        ];
        let mut damage = vec![0usize; 2];
        // Both names are missing, so the charge loop runs once per name;
        // simulate both iterations and assert nothing is charged twice.
        charge_twin_sets(&sets, 0, &sets[0].files[0], &mut damage);
        charge_twin_sets(&sets, 1, &sets[1].files[0], &mut damage);
        assert_eq!(
            damage,
            vec![0, 0],
            "a content-only rule charges every set twice over a dedupe post"
        );
    }
}

/// [`is_a_stray_release`]'s clauses, driven one at a time. Every case is
/// written so that ONE clause is the only thing holding its verdict, so
/// a mutation of that clause kills exactly this test and no other - the
/// per-arm discipline, rather than per-fix.
#[cfg(test)]
mod stray_guard_tests {
    use super::twin_charge_tests::{file, set};
    use super::*;

    /// `offered_names` as [`super::super::emptydesc::names_offered_by_the_post`]
    /// builds it: sanitized and lowercased.
    fn offered(names: &[&str]) -> HashSet<String> {
        names
            .iter()
            .map(|n| nzbkit::disk::sanitize_out_name(n).to_lowercase())
            .collect()
    }

    /// The row this exists for: the set the arrival race left unclaimed
    /// names a file that a set which DID claim describes, so it is the
    /// job's own sibling and not a foreign release's leftovers.
    #[test]
    fn a_sibling_a_claiming_set_describes_is_not_a_stray() {
        let sets = vec![
            set(10_000, vec![file("Twin.bin", 200_000, 7, 9)]),
            set(
                20_000,
                vec![
                    file("Twin.bin", 200_000, 7, 9),
                    file("Other.bin", 50_000, 1, 2),
                ],
            ),
        ];
        assert!(!is_a_stray_release(
            &sets,
            &[false, true],
            &offered(&[]),
            &sets[0].files[0]
        ));
    }

    /// ...and one no claiming set describes still is. Without this the
    /// clause above would be a rule that forgives every set on a post
    /// where anything claimed anything.
    #[test]
    fn a_set_no_claiming_set_describes_is_still_a_stray() {
        let sets = vec![
            set(10_000, vec![file("Twin.bin", 200_000, 7, 9)]),
            set(20_000, vec![file("Other.bin", 50_000, 1, 2)]),
        ];
        assert!(is_a_stray_release(
            &sets,
            &[false, true],
            &offered(&[]),
            &sets[0].files[0]
        ));
    }

    /// The CLAIMS half of the twin clause: a second set naming the same
    /// file is not evidence unless something in this post claimed THAT
    /// set. Without this the rule would forgive every set on a post
    /// carrying two copies of one stray release.
    #[test]
    fn a_twin_that_claimed_nothing_is_not_evidence() {
        let sets = vec![
            set(10_000, vec![file("Twin.bin", 200_000, 7, 9)]),
            set(20_000, vec![file("Twin.bin", 200_000, 7, 9)]),
            set(30_000, vec![file("Other.bin", 50_000, 1, 2)]),
        ];
        assert!(is_a_stray_release(
            &sets,
            &[false, false, true],
            &offered(&[]),
            &sets[0].files[0]
        ));
    }

    /// The NAME half of the identity test: the same bytes under another
    /// name are a different entry in the missing list, with an owner of
    /// their own, so they say nothing about this descriptor.
    #[test]
    fn a_claiming_set_naming_the_same_bytes_differently_is_not_evidence() {
        let sets = vec![
            set(10_000, vec![file("Twin.bin", 200_000, 7, 9)]),
            set(20_000, vec![file("Renamed.bin", 200_000, 7, 9)]),
        ];
        assert!(is_a_stray_release(
            &sets,
            &[false, true],
            &offered(&[]),
            &sets[0].files[0]
        ));
    }

    /// The DIGEST half, one field at a time: two sets naming one file
    /// under different `(length, md5, md5_16k)` describe different
    /// bytes, and charging a set's whole content on a name agreement is
    /// the trade this module's header refuses.
    #[test]
    fn a_claiming_set_declaring_other_bytes_is_not_evidence() {
        for rival in [
            file("Twin.bin", 200_001, 7, 9),
            file("Twin.bin", 200_000, 8, 9),
            file("Twin.bin", 200_000, 7, 10),
        ] {
            let sets = vec![
                set(10_000, vec![file("Twin.bin", 200_000, 7, 9)]),
                set(20_000, vec![rival.clone()]),
            ];
            assert!(
                is_a_stray_release(&sets, &[false, true], &offered(&[]), &sets[0].files[0]),
                "{} / {} / {} was taken for the same file",
                rival.length,
                rival.md5[0],
                rival.md5_16k[0]
            );
        }
    }

    /// A post where nothing claimed anything has no discriminator at
    /// all, and the par-only reading has always been the right one for
    /// it - so the guard must not fire however alone a set looks.
    #[test]
    fn nothing_claimed_anywhere_is_never_a_stray() {
        let sets = vec![
            set(10_000, vec![file("Twin.bin", 200_000, 7, 9)]),
            set(20_000, vec![file("Other.bin", 50_000, 1, 2)]),
        ];
        assert!(!is_a_stray_release(
            &sets,
            &[false, false],
            &offered(&[]),
            &sets[0].files[0]
        ));
    }

    /// A set that claimed something of its own is not a stray by
    /// definition - and it reaches that answer through the SAME clause
    /// as a sibling does, because a descriptor's own set describes it.
    /// That is what makes the separate `set_has_claims[si]` test the
    /// guard used to carry redundant, and why it is gone.
    #[test]
    fn a_set_that_claimed_something_is_never_a_stray() {
        let sets = vec![
            set(10_000, vec![file("Twin.bin", 200_000, 7, 9)]),
            set(20_000, vec![file("Other.bin", 50_000, 1, 2)]),
        ];
        assert!(!is_a_stray_release(
            &sets,
            &[true, true],
            &offered(&[]),
            &sets[0].files[0]
        ));
    }

    /// A name the NZB itself offers is the evidence the packets cannot
    /// carry, and it is what tells the mixture from the stray.
    #[test]
    fn a_name_the_post_offers_is_never_a_stray() {
        let sets = vec![
            set(10_000, vec![file("Twin.bin", 200_000, 7, 9)]),
            set(20_000, vec![file("Other.bin", 50_000, 1, 2)]),
        ];
        assert!(!is_a_stray_release(
            &sets,
            &[false, true],
            &offered(&["Twin.bin"]),
            &sets[0].files[0]
        ));
    }
}
