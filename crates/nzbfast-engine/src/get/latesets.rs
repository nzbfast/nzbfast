//! Finding F12 (capability corpus, 30 Aug 2026): the par2-of-par2
//! CHAIN. The outer set names the obfuscated inner par2 files, they
//! land on disk under their real names - and the inner set, which is
//! what names the PAYLOAD, never activated (its articles were
//! sniff-deferred and reconciled as the outer set's payload). The job
//! then finished "clean" with the payload still hash-named.
//!
//! So: when the job is otherwise good and files remain that no active
//! set names, ask the disk for recovery sets the stream never
//! activated and apply each one. Per-set failures are logged and
//! change nothing - a foreign junk set (the foreign-set-decoy corpus
//! row) must never fail a good job - and a success can only ADD
//! named, verified files. Pinned by
//! `a_par2_of_par2_chain_names_the_payload` and corpus leg
//! n27-par2-of-par2.
//!
//! Wave-4 row W4-06 (30 Aug 2026) is the same finding one directory
//! down: FileDesc publication preserves a safe relative path, so the
//! outer set may legitimately land the inner packet files at
//! `META/inner.par2` - and both halves of this pass were a single
//! top-level `read_dir`, so nothing here could see them. Discovery now
//! asks for `PacketScope::Nested` (bounds in
//! `nzbkit::par2repair::nested`) and `has_unclaimed` walks the tree
//! too. What that widening does NOT get is a set nobody here published:
//! see `published_here`.
//!
//! Wave-4 row W4-01 (30 Aug 2026) is the half F12 left open one level
//! up: WHOSE result counts. This pass ran only on an already-good job
//! and threw every outcome away, which is two defects at once - a
//! repairable job never reached the set that could heal it (W4-01A),
//! and a set that says the payload on disk is NOT the payload it
//! describes was logged and ignored, so the job went green over bytes
//! an authoritative set denies (W4-01B). Both are now folded into the
//! verdict, and the discriminator is `vouched`: an ACTIVE set of this
//! job NAMES one of the late set's packet files, which is a
//! cryptographic statement that it is part of THIS post, so what it
//! then says about the payload is this job's own evidence. That is the
//! same question `published_here` asks about a NESTED packet, asked of
//! the whole set and for a different purpose - one decides whether to
//! run the set at all, the other whether its answer binds - so a
//! root-level set nobody vouches for keeps F12's behaviour exactly:
//! logged, changes nothing, cannot fail the job. This is NOT the
//! foreign-set-decoy rule (corpus row n28), which is about a set that
//! matched nothing at all.
//!
//! Pinned by `a_late_inner_set_repairs_a_missing_payload_article` and
//! `an_inner_set_denial_of_swapped_payload_is_not_green`.
//!
//! X5-24 (30 Aug 2026, a product ruling) is the third question, and the one
//! W4-01's `vouched` deliberately did not ask: not whose ANSWER counts,
//! but what a set nobody vouches for may KEEP. The row predicted this
//! capability was missing and blocked by the stray-set guard in
//! `settle.rs`; probed, the prediction is inverted. A wholly missing
//! member WAS rebuilt byte-exact here - and so was a member of a set
//! for a file the post never offers a slot for, and BOTH of two
//! equal-length wholly missing members. F12's note
//! above says why in as many words ("a success can only ADD named,
//! verified files"), which is nearer "pair up whatever is left over"
//! than a rule. The ruling narrows it: option A then B, residual
//! reconstruction gated on GLOBAL UNIQUENESS, ambiguous and foreign
//! declining, option C rejected.
//!
//! The line the gate sits on is DONOR BYTES, and it is not the line the
//! obvious rule draws. "Apply an unvouched set only when there is one
//! of them and one incomplete slot" is wrong on the very fixture it is
//! meant to allow: only ONE set activates in stream, so every other set
//! is a non-activated candidate - including the one whose payload
//! arrived perfectly and is merely waiting for its real name. Naming a
//! file whose bytes are already on disk under a hash IS F12 and stays
//! ungated. RECONSTRUCTING a member from parity with no bytes of it
//! anywhere is the privileged operation, and it is not visible in the
//! set's packets at all - only in the repair's own report, which
//! arrives after the work is done. So the gate is on KEEPING, not on
//! running: see [`keep_uniquely_assignable_residuals`].
//!
//! Chip-queue row X-4 (31 Aug 2026) is the hole that gate shipped with,
//! and it was a hole in the REPORT rather than in the rule: "did this
//! have bytes of its own to work from" could only be asked of the WHOLE
//! repair, because `nzbkit::par2repair::RepairReport` counted adoption
//! per REPORT. So a leftover two-file set whose first member happened
//! to be on disk under a hash - F12's own shape, legitimately ungated -
//! bought its SECOND member a free pass, and that one was materialised
//! with no uniqueness test at all. `RepairReport::per_file` closes it;
//! [`residual_creations`] is where the direction of the old error was
//! already written down, and now carries what replaced it.
//!
//! Pinned by the `x5_24_*` and `x4_*` probes in `e2e_lateset` - named
//! rather than counted, because that directory now grades more than one
//! row. `get::residual` is the SAME
//! ROW at the other seam - the in-stream stray-release guard, over sets
//! the stream DID activate - and the two are complements rather than
//! duplicates.

use crate::*;
use std::path::Path;
use tracing::{info, warn};

/// How many census rounds the late-set pass may take (W4-12).
///
/// The loop terminates on its own long before this: a round only
/// continues when some set REPAIRED, every repaired id is `settled`
/// forever, and the census over one directory is finite - so the number
/// of continuing rounds is bounded by the number of sets on disk, and a
/// three-level par2-of-par2 chain (the deepest shape anyone has posted)
/// takes three. The cap is the answer to row M4-58's question, which
/// this pass could previously refuse structurally by never looping at
/// all: a reconstruct CYCLE - two sets each naming the other's packet
/// files - cannot spin here, because a cycle needs a set to be run
/// twice and `settled` refuses that, and because this bound holds even
/// if some future arm ever removes an id from it. Eight rather than
/// three so a legitimately deeper chain is not silently truncated;
/// stopping early loses files, which is the direction that matters.
const MAX_LATE_SET_ROUNDS: usize = 8;

/// What the job still owes at the moment the late sets are consulted:
/// the verdict so far, the census's incomplete-file count and the
/// decode/write errors left after the spare rule. Bundled because all
/// three answer one question - is there a shortfall a late set could
/// account for - and because passing them one by one puts this call
/// over the size gate's ceiling for `settle_with_set`. Not a hazard in
/// the abstract: X5-24's fourth field (the NZB-declared byte count per
/// slot, the length band's own input) took that function to 501 lines
/// against a limit of 500 on the first cut, spelled across the call
/// site rather than bundled. Add to the STRUCT, never to the argument
/// list, and keep the construction to one statement.
///
/// The fifth field is the REPAIR PASS'S OWN answer to "what is still
/// outstanding", and it is a different list from the census's. A
/// par2-of-par2 post's sidecar slots are refused by construction and
/// then rebuilt from parity, so the census counts them short forever
/// while `settle::repair::reconcile_obfuscated_aliases` has already
/// excused each one by name ("never arrived whole under its posted
/// name, and the set rebuilt it as ..."). Reading the census list here
/// made the two green tiers below ask an unanswerable question - every
/// slot the download left short must be accounted for, including the
/// ones an earlier pass had already accounted for - so a chain that
/// delivered every byte could never be credited. `None` means no pass
/// could honestly make that claim, and the census list stands.
pub(super) struct Outstanding(
    pub(super) bool,
    pub(super) usize,
    pub(super) u64,
    pub(super) Vec<u64>,
    pub(super) Option<Vec<usize>>,
);

/// Every slot's NZB-declared byte count, indexed the way `slots` is.
///
/// X5-24's length band reads this, and what it is matters more than
/// where it comes from: these are the ENCODED article sizes the NZB
/// declares, summed - yEnc bytes over the wire, not the file's decoded
/// length - and `Segment::bytes`'s own doc calls them approximate. A
/// slot the plan never gave an NZB file, and a file with no segments,
/// answer 0, which [`fits`] refuses outright rather than treating as a
/// match on everything.
pub(super) fn declared_slot_bytes(nzb: &Nzb, slot_file: &[usize]) -> Vec<u64> {
    slot_file
        .iter()
        .map(|&f| {
            nzb.files.get(f).map_or(0, |x| {
                x.segments
                    .iter()
                    .map(|s| s.bytes)
                    .fold(0u64, u64::saturating_add)
            })
        })
        .collect()
}

/// X5-13: has the owner of this job cancelled it?
///
/// Read at every edge where [`apply_nonactivated_disk_sets`] is about to
/// start another expensive thing, and it SAYS SO when it stops. That is
/// not decoration: a pass that quietly did less is indistinguishable in
/// a log from one that found less, and this pass's whole output is a
/// verdict plus some files - so without the line, a cancelled pass and a
/// pass over a directory with nothing in it read identically.
///
/// `None` is never cancelled. No production path passes it - every run
/// carries a handle, and a CLI run's is simply one nobody can reach (see
/// the pass's own note) - so this arm exists for the rows that drive it
/// and for whatever threads a shorter signature later.
fn stopped(cancel: Option<&crate::repair::SideCancel>, edge: &str) -> bool {
    let hit = cancel.is_some_and(crate::repair::SideCancel::is_cancelled);
    if hit {
        info!(
            target: "par2",
            "the late recovery-set pass is stopping {edge} - this job was cancelled"
        );
    }
    hit
}

/// Apply every on-disk recovery set whose id is not among the ACTIVE
/// sets, when unclaimed non-par2 files remain for one to speak about,
/// and hand back the job verdict once they have all spoken.
///
/// `all_good` in, `all_good` out: a VOUCHED set that finds unrepairable
/// damage takes it away, and a vouched set that REPAIRS can give it
/// back - but only when the repair accounts for every slot the download
/// left short and nothing else was wrong. That last condition is why
/// [`Outstanding`] carries the counts and not just the bool: turning a
/// failure into a success is only ever safe when the caller can say
/// what the failure WAS, and the one thing this pass can answer for is
/// a short download whose bytes the late set has now proven.
///
/// The `has_unclaimed` door below is deliberately NOT widened for the
/// verdict's sake. Before W4-01 that door could only ever open more
/// often and never fail a job; now a vouched set CAN, so opening it
/// wider is a real change and not a free one - and there is nothing
/// behind it to find, because a job with nothing unclaimed has every
/// file named by an ACTIVE set, which is the set that already verified
/// it in stream.
///
/// X5-13: IT IS CANCELLABLE, and it was not until 31 Aug 2026. `cancel`
/// is the owner's [`crate::repair::SideCancel`] - the same handle the
/// delete path already aims at this job through `cancel_tail_fetches`,
/// whose ONE production caller logs "the job was deleted", so a raised
/// latch here means exactly that and nothing else.
///
/// EVERY RUN CARRIES ONE, CLI included: `get::install_tail_cancel`
/// builds the handle unconditionally and only REGISTERS it when there
/// is a hub, so a CLI run holds a latch nothing can reach rather than no
/// latch at all - which is what keeps the driver's contract the same
/// everywhere. So the `Option` here is a shape the parameter is threaded
/// in and not a live product state; `None` is what the rows in
/// `cancel_tests` drive the never-cancelled arm with.
///
/// WHY THE ROW GOT WORSE RATHER THAN BETTER. This pass used to run once
/// and return; W4-12 made it a bounded FIXPOINT, so it can now take
/// several census-and-repair rounds and the uncancellable window got
/// LONGER. It also runs only after the otherwise-good settle path, so
/// without a latch a delete waits out a full CPU-and-disk repair of
/// every set on disk and then races finalization.
///
/// CHECKED BETWEEN SETS, NEVER INSIDE ONE, and that is the whole design
/// rather than a detail. `repair_dir_set_with_donors_scoped` writes
/// files: torn down halfway it leaves a set half-applied, which is
/// strictly worse than the wait it saves, and no caller could tell the
/// two apart afterwards. So the latch is read at the top of each ROUND
/// and at the top of each SET, before any repair is started, and the
/// bound it buys is stated in that vocabulary: **at most one more set
/// repair after the latch is raised**. That is a WORK bound and not a
/// clock, which is what makes it assertable on a loaded box - see
/// `cancel_tests`.
///
/// WHAT A CANCELLED PASS RETURNS is whatever it had accumulated, which
/// may be a `good` that a full pass would have turned true. That is the
/// safe direction and it costs nothing: the only thing that raises this
/// latch is a delete, and a deleted job's verdict is never read - park
/// drops the record. Reporting a healthier verdict from a pass that was
/// stopped early would be the unsafe one.
pub(super) fn apply_nonactivated_disk_sets(
    sets: &[Arc<nzbkit::par2::Par2Set>],
    out_dir: &Path,
    slots: &[Arc<FileSlot>],
    extractor: &Arc<nzbkit::extract::Extractor>,
    Outstanding(all_good, incomplete, derrs_net, slot_bytes, outstanding): Outstanding,
    cancel: Option<&crate::repair::SideCancel>,
) -> (bool, Option<crate::repair::RepairShortfall>) {
    let active: std::collections::HashSet<[u8; 16]> =
        sets.iter().map(|s| s.recovery_set_id).collect();
    let named: std::collections::HashSet<String> = sets
        .iter()
        .flat_map(|s| s.files.iter())
        .map(|f| nzbkit::disk::sanitize_out_name(&f.name).to_lowercase())
        .collect();
    if !has_unclaimed(out_dir, &named) {
        return (all_good, None);
    }
    let scope = nzbkit::par2repair::PacketScope::Nested;
    // This pass opts a shortfall INTO patching a member that already
    // exists (claim `shortfall-publish-patch-existing`, 31 Aug 2026),
    // and it is the only caller in the tree that may: the flag is a
    // statement that an `Unrepairable` verdict is the LAST WORD on the
    // set, which the engine cannot see for itself and which is FALSE
    // for `repair::nativepass`' probe - that one runs before a single
    // recovery volume has been bought and the caller goes on to buy
    // them and try again. The late-set pass is the end of the job: it
    // is a bounded fixpoint over the sets no active set claimed, with
    // nothing after it to buy anything. The argument for why patching
    // is safe AT ALL is at `par2repair::status::publishable`; this is
    // only the argument for why it is safe HERE.
    const PATCH_EXISTING: bool = true;
    let mut good = all_good;
    // A vouched set's own Unrepairable arithmetic (below) - the fail
    // message's contract per `failkind::RECOVERY_SHORTFALL_CLAUSE`.
    // Cleared wherever the residual/chain reconciliation below turns
    // `good` back to true, because a shortfall this pass went on to heal
    // is no longer why anything failed. `blocks_over_set`'s `multi=true`
    // is always right here - a vouched set requires a NAMING active set,
    // so the post carries at least two recovery sets whenever this
    // fires.
    //
    // "Kept in step with `good`" is what that said until 1 Sep 2026, and
    // it was never true of the vouched `Err` arm, which fails the job
    // and sets no shortfall at all (there is no block arithmetic to
    // report - the set could not be read). It stopped being true of the
    // tiers too, which cleared it on a job the `denied` set below now
    // keeps failed. Both are ONE-WAY now: a shortfall is only ever
    // cleared beside a `good` this pass can still stand behind, and a
    // failed job with no shortfall clause is the Err arm's shape rather
    // than a lost one.
    let mut late_shortfall: Option<crate::repair::RepairShortfall> = None;
    // What the CENSUS can see, which is the population the counting
    // cross-check below is about, and what is genuinely still
    // outstanding, which is the population the accounting is about.
    // They are the same list on every path that ran no repair; on a
    // par2-of-par2 post they are not - see [`Outstanding`]'s fifth
    // field.
    let census = incomplete_slots(slots);
    let short = outstanding.unwrap_or_else(|| census.clone());
    // BOTH candidate lists accumulate ACROSS the rounds and both
    // verdicts stay after the last one - the note this loop's chain tier
    // left for whoever made it a fixpoint, and it is right: a set that
    // heals in round two is exactly the shape that tier exists for, and
    // accounting per round asks each round to carry the whole shortfall
    // alone.
    let mut residual: Vec<Residual> = Vec::new();
    let mut chained: Vec<Chained> = Vec::new();
    // X5-10: nothing this pass proves spent is deleted until every set
    // has had its turn - the sweep is the last statement below.
    let mut spent: Vec<PathBuf> = Vec::new();
    // Sets this pass is FINISHED with: one that repaired, or one that
    // verified clean. A set that FAILED is deliberately absent, which
    // is X5-11's whole row - a set skipped for a missing index packet
    // that another set in the same pass then materialises has to be
    // asked again.
    let mut settled: std::collections::HashSet<[u8; 16]> = std::collections::HashSet::new();
    // Failures already reported, so a set retried across rounds is
    // explained once rather than once per round.
    let mut said: std::collections::HashSet<[u8; 16]> = std::collections::HashSet::new();
    // W4-01B, re-closed 1 Sep 2026: which VOUCHED sets are currently
    // saying the bytes on disk are not the bytes they describe.
    //
    // `good` alone cannot carry that, and this is the whole finding: it
    // is one bool with no memory of WHY it went false, so a `good =
    // false` written by the vouched `Unrepairable`/`Err` arms below is
    // indistinguishable from an incoming short download - and the two
    // post-loop tiers, which landed a day after W4-01B, test `!good` and
    // nothing else before setting it back to true. A post carrying BOTH
    // a whole-file loss those tiers can account for AND a second vouched
    // set over a member whose on-disk bytes are somebody else's then
    // reported Completed over bytes an authoritative set had denied.
    // (The denial-only shape was always safe and still is: nothing is
    // short, so every tier declines on `short.is_empty()`.)
    //
    // A MEMBERSHIP and not a counter, because a denial is WITHDRAWN by
    // the same set healing: the pass is a bounded fixpoint, a failed set
    // is deliberately not `settled` and so is re-run every round, and a
    // set that denies in round one and repairs in round two has answered
    // its own denial. Removing on `Repaired`/`NoDamage` is what keeps
    // every chain that completes today completing.
    let mut denied: std::collections::HashSet<[u8; 16]> = std::collections::HashSet::new();
    // X5-13: how many set repairs this pass started, and how many of
    // them it started with the latch already raised. The second is the
    // number the row grades and its bound is ONE - the repair in flight
    // when the delete landed cannot be taken back, and every one after
    // it must not begin.
    let mut repairs = 0usize;
    for _ in 0..MAX_LATE_SET_ROUNDS {
        // X5-13, the ROUND edge. A cancelled job takes no further
        // census: `disk_sets_scoped` walks and PARSES every par2 file
        // in the directory, which on a big post is the second-longest
        // thing here after the repair itself.
        if stopped(cancel, "before its next census round") {
            break;
        }
        let Ok(found) = nzbkit::par2repair::disk_sets_scoped(out_dir, scope) else {
            break;
        };
        // What the door looked at, the repair behind it must be able to
        // reach - see the M4-102 note on `has_unclaimed`. Re-derived per
        // round with the census: applying a set publishes files, and
        // publication preserves a relative path, so a round can create
        // the very subdirectory the next round's adoption scan needs.
        let donors = nzbkit::par2repair::nested_subdirs(out_dir).unwrap_or_default();
        // F6 (1 Sep 2026): which of the discovered sets may vote on a
        // CONTESTED destination name - the sets this pass can actually
        // apply, and nothing else.
        //
        // The engine's Nested walk sees every recovery set under
        // `out_dir`, including one that came out of an extracted archive
        // and lives only in a subdirectory. `published_here` refuses
        // such a set in EVERY round (`named` is derived once from the
        // active sets and never grows), so it can never land a file -
        // yet its FileDesc names still made the engine disambiguate a
        // running set's target onto `<name>.dup-<fid>`, which is a
        // payload kept under a name no *arr imports plus a second copy
        // beside the damaged original. ACTIVE sets stay in: their files
        // are already on disk under the declared name, so contesting
        // against them is exactly right.
        //
        // Derived from `found` before the loop consumes it, and not from
        // the loop's own skip test, because `contested` is a property of
        // the whole ROUND: the first set repaired must be disambiguated
        // against the last set this round will reach, not only against
        // the ones already visited. `settled` is deliberately absent for
        // the same reason - a set that has already landed its files
        // still owns those names.
        //
        // AND IT IS A SNAPSHOT, so it is RE-TAKEN whenever a repair
        // creates a packet file under this tree (the second half of F6,
        // 1 Sep 2026). Each `repair_dir_set_with_donors_scoped` builds
        // its own catalog off the CURRENT directory, and in the
        // par2-of-par2 shape a repair can recreate a missing
        // `inner.par2` mid-round: that set then enters the next
        // catalog, is absent from this snapshot, and its descriptors
        // are dropped from the claim tally - where before F6 they
        // voted. Narrowing `contested` by a stale list is the one
        // direction that can LOSE a name, so the list is refreshed
        // rather than left to the next round.
        let applicable = applicable_ids(out_dir, &named, &active, &found);
        let mut progress = false;
        // Set when a repair in this round CREATES a packet file, which
        // ends the round early so the next one re-censuses - see the
        // arm that sets it.
        let mut stale_census = false;
        for (id, packets) in found {
            // X5-13, the SET edge and the one that carries the bound.
            // BEFORE the skip tests below rather than after them, so a
            // cancelled pass stops on the first set it looks at instead
            // of walking to the first one it would have repaired.
            if stopped(cancel, "before starting another set") {
                break;
            }
            if active.contains(&id)
                || settled.contains(&id)
                || !published_here(out_dir, &named, &packets)
            {
                continue;
            }
            let mine = vouched(out_dir, &named, &packets);
            repairs += 1;
            let done = nzbkit::par2repair::repair_dir_set_with_donors_scoped(
                out_dir,
                &id,
                &donors,
                scope,
                PATCH_EXISTING,
                Some(&applicable),
            );
            match done {
                Ok(nzbkit::par2repair::RepairStatus::Repaired(r)) => {
                    settled.insert(id);
                    // A repair that CREATED a packet file has changed
                    // what every later catalog in this round will see,
                    // and `applicable` above is a snapshot taken before
                    // it existed (F6, second half, 1 Sep 2026). In the
                    // par2-of-par2 shape a repair recreates a missing
                    // `inner.par2`: that set is then IN the next
                    // catalog and ABSENT from the snapshot, so its
                    // descriptors are dropped from the claim tally
                    // where before F6 they voted - and narrowing
                    // `contested` by a stale list is the one direction
                    // that can lose a name.
                    //
                    // The round ENDS instead of re-censusing here: the
                    // round loop's own `disk_sets_scoped` is the single
                    // census this pass is allowed (a second call inside
                    // the set loop is a re-scan per set, which
                    // `the_late_set_pass_is_a_bounded_fixpoint` refuses
                    // by depth and W4-12 priced), and a `Repaired` has
                    // already set `progress`, so the next round runs
                    // with a fresh census and `settled` keeps this set
                    // from repeating. Bounded by MAX_LATE_SET_ROUNDS
                    // like everything else here. The sniff is over this
                    // repair's own creations only, so the cost of
                    // asking is a few file heads.
                    stale_census = created_a_packet_file(&r);
                    // This set has answered whatever it said in an
                    // earlier round: the damage it could not repair
                    // then is repaired now.
                    denied.remove(&id);
                    // Only a REPAIR is progress. `NoDamage` writes
                    // nothing, so it can never be what puts a set the
                    // census has not seen yet on disk, and counting it
                    // would buy a round that can only repeat itself.
                    progress = true;
                    // `files_created` is a SUBSET of `files_patched` (the
                    // engine pushes both for a file it had to create), so
                    // adding them said "2 file(s) landed" about one file.
                    info!(
                        target: "par2",
                        "a recovery set that never activated in-stream was applied \
                         from disk: {} file(s) landed",
                        r.files_patched.len()
                    );
                    if mine
                        && !good
                        && let Some(redundant) = repair_accounts_for_the_shortfall(
                            &r,
                            &short,
                            slots,
                            extractor,
                            out_dir,
                            incomplete,
                            census.len(),
                            derrs_net,
                        )
                    {
                        good = true;
                        spent.extend(redundant);
                    }
                    if mine {
                        chained.extend(chain_creations(&r));
                    } else {
                        residual.extend(residual_creations(&r));
                    }
                    spent.extend_from_slice(&r.consumed_sources);
                }
                Ok(nzbkit::par2repair::RepairStatus::NoDamage) => {
                    settled.insert(id);
                    // Same withdrawal as the arm above, for the set that
                    // was unreadable or short a round ago and now
                    // verifies clean off disk.
                    denied.remove(&id);
                }
                // BOTH shortfall arms below LOG a partial publish and
                // feed NOTHING ELSE from it. Since 31 Aug 2026 the engine
                // no longer returns before writing: a member of a short
                // set whose own blocks were all present or adopted is
                // CREATED under its FileDesc name and whole-file-MD5
                // verified anyway, which is the whole of what the user
                // was losing (claim `unrepairable-per-file-publish-impl`).
                // Three deliberate omissions, one per candidate list:
                //
                // `chained` - because feeding it can flip `good` back to
                // true through `chain_accounts_for_the_shortfall` below,
                // and a set whose own arithmetic says the bytes on disk
                // are not the bytes it describes must not green its own
                // job. A partial publish ADDS a verified file; it never
                // decides whether the download healed.
                //
                // `residual` - because there is nothing to gate. X5-24
                // exists for a member rebuilt from PARITY ALONE, and a
                // shortfall runs no parity pass, so every file it can
                // publish is one the adoption scan proved byte-exact -
                // `residual_creations` returns empty on this report by
                // construction (`file_had_bytes_on_disk` is true of every
                // one of them).
                //
                // `spent` - because `consumed_sources` is always empty on
                // this verdict; see its note on
                // `nzbkit::par2repair::RepairStatus::Unrepairable`.
                Ok(nzbkit::par2repair::RepairStatus::Unrepairable {
                    needed,
                    have,
                    adopted,
                    partial,
                }) if mine => {
                    if said.insert(id) {
                        warn!(
                            target: "par2",
                            "a recovery set this job's own set vouches for finds {needed} \
                             block(s) of damage it cannot repair ({have} recovery block(s) on \
                             hand, {adopted} adopted) - the bytes on disk are not the bytes it \
                             describes, so this is not a clean download{}",
                            nzbkit::par2repair::published_clause(&partial)
                        );
                    }
                    good = false;
                    denied.insert(id);
                    late_shortfall = crate::repair::blocks_over_set(needed, have, id, true);
                }
                Ok(nzbkit::par2repair::RepairStatus::Unrepairable { partial, .. }) => {
                    if said.insert(id) {
                        info!(
                            target: "par2",
                            "a non-activated recovery set on disk matched nothing here - ignored{}",
                            nzbkit::par2repair::published_clause(&partial)
                        );
                    }
                }
                Err(e) if mine => {
                    if said.insert(id) {
                        warn!(
                            target: "par2",
                            "a recovery set this job's own set vouches for could not be read \
                             ({e}) - refusing to report success over files nothing verified"
                        );
                    }
                    good = false;
                    denied.insert(id);
                }
                Err(e) => {
                    if said.insert(id) {
                        info!(target: "par2", "non-activated set skipped: {e}");
                    }
                }
            }
            if stale_census {
                // See the `Repaired` arm: `applicable` no longer
                // describes the directory, so no later set in THIS
                // round may narrow its contest by it.
                break;
            }
        }
        if !progress {
            break;
        }
    }
    // X5-13: what a cancelled pass actually cost, in the vocabulary the
    // row's bound is stated in. Said only when the latch is up, because
    // on every other run the number is the whole story of the pass and
    // the lines above have already told it set by set.
    if cancel.is_some_and(crate::repair::SideCancel::is_cancelled) {
        info!(
            target: "par2",
            "the late recovery-set pass stopped early for a cancelled job \
             after {repairs} set repair(s)"
        );
    }
    // The chain family's assignment, computed FIRST and read by BOTH
    // gates below, which is the 1 Sep 2026 fix: asking the two families
    // separately let one lost slot be both a foreign rebuild's unique
    // fit and a vouched rebuild's, so the foreign file was kept under a
    // real name while the chain tier credited the slot. See
    // [`chain_assignment`].
    let chain_by_slot = chain_assignment(&chained, &short, &slot_bytes, slots);
    // X5-24, and it runs AFTER the loop because the question is global:
    // whether a rebuild is uniquely assignable cannot be answered while
    // another set that has not run yet may produce a second candidate
    // for the same slot.
    let assigned =
        keep_uniquely_assignable_residuals(&residual, &chain_by_slot, &short, &slot_bytes, slots);
    if !good
        && residual_accounts_for_the_shortfall(
            &assigned,
            &short,
            incomplete,
            census.len(),
            derrs_net,
            !denied.is_empty(),
        )
    {
        good = true;
        late_shortfall = None;
    }
    // The CHAIN tier, and it runs after that one for the same global
    // reason: a slot's rebuild may come from any set in the chain, and
    // which set produced it is not decidable until every one of them
    // has run.
    //
    // FOR WHOEVER MAKES THIS LOOP A FIXPOINT (W4-12 asks for one): both
    // candidate lists have to accumulate ACROSS the rounds and both
    // verdicts have to stay here, after the last one. A set that heals
    // in round two is exactly the shape this tier exists for, and a
    // fixpoint that runs the accounting per round asks each round to
    // carry the whole shortfall alone - which is the very mistake this
    // commit fixed one level down, where the pass was asked to account
    // for slots an earlier pass had already accounted for.
    if !good
        && chain_accounts_for_the_shortfall(
            &assigned,
            &chain_by_slot,
            &chained,
            &short,
            slots,
            incomplete,
            census.len(),
            derrs_net,
            !denied.is_empty(),
        )
    {
        good = true;
        late_shortfall = None;
    }
    // W4-01B has the LAST WORD, after every tier above and whatever the
    // in-loop flip decided.
    //
    // The two tiers are already gated, and this is the belt for the one
    // green they do not own: the `mine && !good` flip inside the loop.
    // That one is not terminal in the ordinary shape - a denying set is
    // never `settled`, so it re-runs and re-asserts `good = false` in
    // the round the flip's own `progress` bought - but "not terminal"
    // stops being true at `MAX_LATE_SET_ROUNDS`, where the loop ends on
    // the cap rather than on a round with nothing left to say. Gating
    // that flip instead was the other option and is rejected: a set that
    // denies in round one and heals in round two would have had its
    // sibling's in-loop green blocked at a moment `denied` was legitimately
    // non-empty, and no later round re-offers it (the sibling is
    // `settled`), so a job that completes today would stop. Withdrawal
    // on `Repaired`/`NoDamage` makes the test here safe in a way it
    // cannot be made there.
    if !denied.is_empty() {
        good = false;
    }
    // Last of all, after every set has run and every rebuild has been
    // judged: X5-10's invariant, and the reason it is the last statement
    // in the function rather than a line inside the loop.
    crate::repair::sweep_spent_sources(&spent);
    (good, late_shortfall)
}

/// A member a VOUCHED late set rebuilt - the chain tier's candidate.
///
/// The X5-24 [`Residual`] beside it is the same shape asked a WEAKER
/// question, and the difference is the whole reason the two are not one
/// type. A residual comes from a set NOTHING vouches for, so the gate
/// over it is a decidability test whose losing arm DELETES the file
/// ([`decline`]); this one comes from a set an ACTIVE set of this job
/// cryptographically names, so the file is this download's whatever the
/// band says and nothing here may remove it. Only the VERDICT is at
/// stake, so the losing arm is silence.
///
/// No `path`, for that reason: there is nothing to delete.
struct Chained {
    /// The FileDesc name, exactly as the repair reported it.
    name: String,
    /// The rebuilt file's length on disk. The repair MD5-proved it
    /// before returning `Repaired`.
    len: u64,
}

/// A member some non-activated set rebuilt from PARITY ALONE - no bytes
/// of it were anywhere on disk, under its own name or anybody else's.
#[derive(Debug)]
struct Residual {
    /// The FileDesc name, exactly as the repair reported it. A LABEL
    /// for the log and nothing more since X-8: it is not unique (two
    /// descriptors may declare one name) and it does not resolve to
    /// this file (`path` below is where the repair actually put it).
    name: String,
    /// Where the repair LANDED this target -
    /// [`nzbkit::par2repair::FileRepair::path`], never a path rebuilt
    /// from `name`. See [`residual_creations`]'s X-8 section.
    path: PathBuf,
    /// The rebuilt file's length on disk, which is the FileDesc's
    /// declared DECODED length (the repair MD5-proved it before
    /// returning `Repaired`).
    len: u64,
}

/// The files this repair created out of nothing, when it had nothing of
/// its own to work from.
///
/// The evidence that excuses a rebuild is that the set matched one of
/// its own FileDesc/IFSC hashes against bytes something else already
/// put here - it adopted a hash-named file, or patched a partial that
/// was on disk. That is a cryptographic statement that the set belongs
/// where it ran, the same evidence `vouched` looks for one level up,
/// and F12's whole reason for existing. A set with none of it has told
/// us only that it is internally consistent.
///
/// # X-4 (31 Aug 2026): the question is asked PER FILE now
///
/// It used to be asked of the whole repair, because
/// [`nzbkit::par2repair::RepairReport`] could not answer it any other
/// way: `blocks_adopted`, `adopted_from` and `consumed_sources` are
/// totals, so they say that SOME member had bytes here and never which
/// one. A set that adopted one member out of a hash-named donor and
/// rebuilt another purely from parity therefore left the SECOND one
/// ungated, credited with what the first earned - a multi-file release
/// where one member arrived hash-named and another was wholly missing
/// got the missing one materialised with no uniqueness test at all.
/// That was the correct direction to be wrong in (it keeps files rather
/// than deleting them) and it was documented here rather than hidden,
/// but it was a hole: `report.per_file` closes it, and
/// [`nzbkit::par2repair::RepairReport::file_had_bytes_on_disk`] is the
/// question, fail-closed on every uncertainty so the doubt still keeps
/// the file.
///
/// Strictly a TIGHTENING, and only over sets nothing vouches for: a
/// created file that adopted is excused exactly as before, a created
/// file that adopted nothing now reaches
/// [`keep_uniquely_assignable_residuals`] instead of skipping it, and
/// nothing that was gated before is ungated now. The two global clauses
/// this replaces are gone rather than kept as belt, and deliberately:
/// `consumed_sources` non-empty means a donor fed SOME target, which is
/// the same credit-by-sibling; and `files_patched.len() >
/// files_created.len()` means some OTHER member was patched in place,
/// which is that member's evidence and never this one's. A file in
/// `files_created` did not exist when the repair began, so it has no
/// in-place patch of its own to point at.
///
/// # X-8 (31 Aug 2026): the PATH comes from the census too
///
/// The population is `per_file` and the path is
/// [`nzbkit::par2repair::FileRepair::path`], where both used to be a
/// name out of `files_created` with
/// `join_out_name(out_dir, n)` guessed back from it. The guess was
/// wrong wherever the repair had to DISAMBIGUATE: two descriptors whose
/// names sanitize to one destination would otherwise share a file, so
/// the second lands at `<name>.dup-<first 6 bytes of file_id>` - and
/// this function then built a path the repair never wrote, found
/// nothing there, and yielded no residual at all. The rebuild the gate
/// exists to refuse was the one rebuild it could not see.
///
/// **MEASURED red 31 Aug 2026** on `e2e_lateset::x8_*`:
/// `Not.Ours.Dup.bin.dup-673dcaa8b1ab`, 100,000 bytes of a leftover
/// release, left in the output directory, while BOTH of the gate's
/// declines landed on the one path a name could reach - the second
/// `remove_file` failing `No such file or directory` on a path the
/// first had already unlinked.
///
/// Keying [`Residual`] on that path is what makes the double-decline go
/// away rather than merely become rarer: two targets are now two
/// residuals at two paths, so [`decide`]'s "more than one leftover set
/// fits the same lost file" is said about two real files or not at all.
///
/// The adoption question is still asked by NAME through
/// [`nzbkit::par2repair::RepairReport::file_had_bytes_on_disk`], which
/// is unchanged and still fails closed - a name with no census entry,
/// or one of two same-named entries adopting, still keeps the file.
/// The narrower per-entry question that path identity now makes
/// decidable is a separate ruling and is deliberately not taken here.
fn residual_creations(r: &nzbkit::par2repair::RepairReport) -> Vec<Residual> {
    r.per_file
        .iter()
        .filter(|f| !r.file_had_bytes_on_disk(&f.name))
        .filter_map(|f| {
            // The path the repair LANDED this target at (X-8), never a
            // guess rebuilt from `f.name`.
            let path = f.path.clone();
            // A ZERO-LENGTH creation is out of this row's scope in both
            // directions, and skipping it is deliberate rather than an
            // oversight of the band. It carries no length to be
            // assigned by, so it could only ever be declined; what the
            // skip buys is that it is not DELETED either.
            //
            // X-6 (30 Aug 2026) read the `super::emptydesc` half of
            // that reasoning and it needed narrowing, though not
            // reversing. Emptydesc's OWN materializations can never be
            // in this population: `land_zero_length_filedescs` runs
            // earlier in the same settle pass, so its file is already
            // there when the late repair looks, and `files_created` is
            // by definition the targets that did not exist. What the
            // skip actually holds is a zero-length member of a set
            // emptydesc never saw - a late set is not an ACTIVE one -
            // reached only on the `!mine` arm, so nothing vouches for
            // it. Which way THAT should go is the boundary question
            // between the two families, and both sides of it point at
            // dropping: emptydesc already declines a zero-length
            // descriptor from an active set that claimed nothing once
            // some other set has claimed, and X5-24 declines whatever
            // the post cannot decide. Neither is a ruling about a
            // VIDEO_TS placeholder from a set of unknown provenance,
            // which is what this is, so it is left exactly as it
            // stands and handed to emptydesc rather than settled from
            // this side.
            //
            // An unreadable creation lands here too, for a different
            // reason that happens to give the same answer: nothing to
            // decide with, and nothing this pass could delete either.
            let len = std::fs::metadata(&path).map_or(0, |m| m.len());
            (len > 0).then(|| Residual {
                name: f.name.clone(),
                path,
                len,
            })
        })
        .collect()
}

/// The X5-24 gate: keep a purely-parity-reconstructed member only where
/// the post itself decides which loss it is, and DELETE the rest.
///
/// Returns, for each short slot, the residual assigned to it - so the
/// verdict half below can ask whether the assignment covers everything
/// the download left short.
///
/// # The rule
///
/// A residual is kept when exactly one wholly missing slot fits it AND
/// no other residual fits that slot. Mutual uniqueness, both directions,
/// with no first-match tie-break anywhere: set order follows packet
/// arrival, so a rule that picked would give different answers on
/// different nights. Two equal-length losses decline; a set for a file
/// the post never offers a slot for fits nothing and declines.
///
/// AND SINCE 1 Sep 2026 a fourth decline, `chain_by_slot`: a slot the
/// CHAIN family already uniquely fits is not a loss this family may be.
/// The rule was asked of the two families' tables separately, so each
/// candidate looked unique from inside its own list and both were
/// accepted - the foreign file KEPT under a real name while the chain
/// tier credited the slot. The veto is deliberately ASYMMETRIC and
/// cannot cost a green: it only ever fires on a slot
/// [`chain_accounts_for_the_shortfall`] itself accounts for, so the job
/// still reaches that tier's coverage test with the slot covered.
///
/// It runs on an already-GOOD job too, and that is deliberate: a
/// foreign set's file has no more business in the output directory of a
/// job that finished clean than in one that did not, and a job with
/// nothing outstanding has no loss for a rebuild to be, so every
/// residual it produced declines. The one shape that costs is a slot
/// the census does not count as short - a skipped sample, a deferred
/// volume - whose member some leftover set rebuilds anyway; that file
/// goes, which is the same answer the setting that skipped it already
/// gave.
///
/// # Why the file is deleted rather than left
///
/// Only ever a file THIS repair created (`files_created` is the targets
/// that did not exist when the repair began), so nothing a declined
/// delete removes was here before the job ran, and nothing the job
/// verified is touched. Leaving it is not the conservative option: it
/// is another release's payload sitting in this download's output
/// directory under a real name, which is what an *arr imports.
///
/// # What it deliberately cannot do
///
/// It proves nothing about ownership. The bytes are proven - the repair
/// MD5-checked them - but that a set is THIS post's is exactly what a
/// leftover set carries no evidence of, which is why the rule is a
/// decidability test and why the ruling was a product decision rather
/// than a measurement. The lever if it ever needs narrowing is the
/// BAND, not the counts.
///
/// # Why a PARTIAL slot is not the adopted case (X-5, 30 Aug 2026)
///
/// [`lost_whole`] wants every segment missing, so a slot that received
/// some bytes and is still short declines even where the band would
/// decide it. X-5 asked whether that could be relaxed the way
/// [`repair_accounts_for_the_shortfall`] relaxes it - sweep the partial
/// as redundant once the set has proved the file whole. It cannot, and
/// the two reasons are independent.
///
/// FIRST, THE PARTIAL IS AN ADOPTION CANDIDATE, so the two populations
/// barely meet. `par2repair::adopt`'s candidate walk takes every
/// regular non-recovery, non-identified file in the repair directory,
/// and the sliding scan finds a member's block in one at any offset -
/// `sliding_scan_adopts_shifted_block_content_from_a_fragment` in
/// `crates/nzbkit-base/src/par2repair/unit_tests.rs` pins that off a
/// ten-byte-shifted junk-named fragment carrying one block. A hit in
/// the partial raises the adopted count OF THE MEMBER THAT PARTIAL IS A
/// FRAGMENT OF - which is the very member whose slot is short - and
/// [`residual_creations`] then yields nothing for it. So a residual
/// coexisting with its own partial is precisely the case where the set
/// matched no byte of that partial: there is no evidence there to
/// relax on, only a length.
///
/// THAT REASONING WAS REPORT-WIDE UNTIL X-4 (31 Aug 2026), when the
/// same question started being asked per TARGET, and the narrowing
/// leaves this arm saying less than it did: any hit anywhere used to
/// kill every residual of the report, so the sentence above could be
/// written about the whole set at once. It still covers the ordinary
/// shape, and covers it more exactly than the blunt version did - the
/// member excused is now the member the evidence is about. What it no
/// longer covers is a partial whose blocks adopt into some OTHER
/// member; that one is carried entirely by the second reason below,
/// which is unconditional, so the conclusion does not move. The pin is
/// `a_repair_with_a_tie_to_disk_produces_no_residual_for_THAT_member`,
/// and this paragraph is what it exists to stop being retired in
/// silence. Stated limit, because the two walks do
/// differ: adoption reads the root and the donor directories, where
/// discovery and `has_unclaimed` are tree-aware (W4-06), so a partial
/// published at a tree path is not a candidate. A SHORT slot's file is
/// at the root - publication to a tree path is something settle does to
/// a verified file - so that gap is not the ordinary shape.
///
/// SECOND, AND UNCONDITIONALLY, THE ANALOGY IS INVERTED.
/// [`repair_accounts_for_the_shortfall`] runs only when `mine`, an
/// ACTIVE set of this job having named one of the late set's packet
/// files, and it sweeps a partial the repair's own MD5-proved read
/// CONSUMED or ADOPTED FROM - a cryptographic statement that the
/// partial is a copy of that member. [`residual_creations`] runs only
/// when `!mine`. Doing "the same" here would delete bytes this job
/// downloaded off the wire, on the strength of the length band alone,
/// for a set nothing vouches for: a strictly weaker basis for a
/// strictly more destructive act. The adopted path's sweep is not a
/// precedent for this one, it is its opposite.
fn keep_uniquely_assignable_residuals(
    residual: &[Residual],
    chain_by_slot: &[Option<usize>],
    short: &[usize],
    slot_bytes: &[u64],
    slots: &[Arc<FileSlot>],
) -> Vec<Option<usize>> {
    let mut assigned: Vec<Option<usize>> = vec![None; short.len()];
    if residual.is_empty() {
        return assigned;
    }
    let lens: Vec<u64> = residual.iter().map(|r| r.len).collect();
    for (i, (r, verdict)) in residual
        .iter()
        .zip(assign_by_length(&lens, short, slot_bytes, slots))
        .enumerate()
    {
        match verdict {
            Err(why) => decline(r, why),
            // The cross-family veto (1 Sep 2026). See
            // [`chain_assignment`]: [`decide`] answered inside this
            // family's table alone, so a slot a VOUCHED set's rebuild
            // already is could still take a foreign rebuild of the same
            // band, and the file stayed on disk under a real name.
            Ok(k) if chain_by_slot.get(k).is_some_and(Option::is_some) => decline(
                r,
                "a recovery set this job's own set vouches for rebuilt that lost \
                 file, so this one cannot be it",
            ),
            Ok(k) => {
                info!(
                    target: "par2",
                    "{}: a recovery set the stream never activated rebuilt this file \
                     from its parity alone, and the post admits exactly one loss it \
                     can be - {} declared byte(s) against {} rebuilt",
                    r.name,
                    slot_bytes.get(short[k]).copied().unwrap_or(0),
                    r.len,
                );
                assigned[k] = Some(i);
            }
        }
    }
    assigned
}

/// Which short slot each candidate rebuild is, by X5-24's rule: the
/// length band, and mutual uniqueness both ways.
///
/// The answer is per CANDIDATE and in candidate order - `Ok(k)` naming
/// the entry of `short` it is, or the reason it cannot be decided.
///
/// ONE rule, two consumers, and that is the point of it having its own
/// function. [`keep_uniquely_assignable_residuals`] turns a decline into
/// a DELETE, because a rebuild from a set nothing vouches for is another
/// release's payload sitting in this download's directory; the chain
/// tier turns one into silence, because a rebuild from a set an ACTIVE
/// set names is this download's file whatever the band says. A second
/// spelling of the band or of the uniqueness test would be two gates
/// that agree until the day somebody moves one.
///
/// A slot that received SOME bytes is out, via [`lost_whole`]: the
/// ruling is about a member lost WHOLE, and a slot with a partial on
/// disk raises a second question (whose bytes win) that no count here
/// can answer. Relaxing that to match the adopted-source sweep is X-5,
/// and [`keep_uniquely_assignable_residuals`]'s doc says why the two are
/// opposites rather than neighbours.
fn assign_by_length(
    lens: &[u64],
    short: &[usize],
    slot_bytes: &[u64],
    slots: &[Arc<FileSlot>],
) -> Vec<std::result::Result<usize, &'static str>> {
    let fitting: Vec<Vec<usize>> = lens
        .iter()
        .map(|&len| {
            (0..short.len())
                .filter(|&k| {
                    let s = short[k];
                    lost_whole(&slots[s])
                        && fits(
                            len,
                            slot_bytes.get(s).copied().unwrap_or(0),
                            slots[s].total_segments as u64,
                        )
                })
                .collect()
        })
        .collect();
    (0..lens.len()).map(|i| decide(&fitting, i)).collect()
}

/// The decision itself, over nothing but the fit table, so it can be
/// driven directly - `fitting[i]` is the short slots residual `i` could
/// be. Mutual uniqueness both ways: exactly one loss fits this rebuild,
/// and no other rebuild fits that loss.
///
/// Three declines, three different facts, and they are worth separating:
/// nothing fits, several losses fit, or one loss fits and another
/// leftover set fits it too. A reader deciding whether the gate is too
/// tight needs to know which of the three they are looking at.
fn decide(fitting: &[Vec<usize>], i: usize) -> std::result::Result<usize, &'static str> {
    let [k] = fitting[i][..] else {
        return Err(if fitting[i].is_empty() {
            "this post lost no whole file of that size"
        } else {
            "this post lost more than one whole file of that size, so which \
             of them this is cannot be decided from the post"
        });
    };
    if fitting.iter().filter(|f| f.contains(&k)).count() != 1 {
        return Err(
            "more than one leftover set fits the same lost file, so which \
                    loss this one is cannot be decided from the post",
        );
    }
    Ok(k)
}

/// Say what was declined and why, then remove it. A silent decline is
/// how the next reader concludes the capability was never there - which
/// is exactly what X5-24's own row concluded about the version of this
/// pass that declined nothing.
fn decline(r: &Residual, why: &str) {
    warn!(
        target: "par2",
        "{}: a recovery set the stream never activated rebuilt this file from \
         parity alone, but {why} - the {} rebuilt byte(s) are not this download's \
         to keep, so they are dropped rather than left in the output directory",
        r.name,
        r.len,
    );
    if let Err(e) = std::fs::remove_file(&r.path) {
        warn!(target: "par2", "{}: could not drop the declined rebuild: {e}", r.name);
    }
}

/// A slot that delivered nothing at all - every segment missing.
///
/// `total_segments` at zero would make this vacuously true, so it is
/// refused: a slot with no segments has lost nothing.
fn lost_whole(s: &Arc<FileSlot>) -> bool {
    s.total_segments > 0 && s.missing.load(Ordering::Relaxed) >= s.total_segments
}

/// Could a rebuilt file of `len` DECODED bytes be the slot the NZB
/// declares `encoded` bytes over `segments` articles for?
///
/// A band and never an equality, and the reason is that the two numbers
/// are not the same measurement: the NZB declares yEnc-ENCODED article
/// sizes, the rebuilt file is the decoded payload, and `Segment::bytes`
/// is documented approximate on top of that. A zero on either side is
/// refused outright rather than matching everything.
///
/// # It is not this module's own rule any more (31 Aug 2026)
///
/// This was a flat 0.9..1.5 RATIO, written here, while
/// `settle::repair::alias_size_band` asked the identical physical
/// question one seam earlier under a different rule - 0.9..1.2 plus a
/// per-article framing allowance, derived from the two parts yEnc's
/// cost actually has (a proportional payload part, and a constant
/// `=ybegin`/`=ypart`/`=yend` part that a ratio cannot model). One fact,
/// two spellings, which is what `tools/par2-rule-gate.py` refuses one
/// directory over - and they had already parted.
///
/// THE RATIO'S UPPER HALF IS WHAT PARTED, and X-7's own note above this
/// function had already named it: "the whole upper half of it is dead
/// space no honest encoding reaches". Dead space is not free. Measured
/// 31 Aug 2026 on the three-level chain fixture, a rebuilt
/// `setc.vol03+4.par2` of 42,008 bytes fitted BOTH its own slot
/// (declared 43,587) and the next volume up (declared 53,947, a ratio
/// of 1.284) - so [`decide`] refused one for "more than one whole file
/// of that size" and the other for "more than one leftover set fits the
/// same lost file", two of five sidecar slots went unaccounted, and
/// `chain_accounts_for_the_shortfall` declined on a job that had
/// delivered every byte byte-exact. Under the shared band the five
/// rebuilds and the five losses pair one to one.
///
/// X-7 asked for the encoded-over-decoded distribution to be MEASURED
/// before this number moved, and that is still not what happened: what
/// replaced it is a DERIVED model with a measured framing constant,
/// already shipping against the same real-world NZB byte counts one
/// seam earlier. That is the justification X-7 wanted in kind if not in
/// form, and it is strictly better than a second guess. The lever is
/// still the band and never the counting clauses beside it - but the
/// band is now over there, and moving it moves both seams at once,
/// which is the point.
///
/// WHAT THE TIGHTENING COSTS, stated rather than left to be found,
/// because on the residual path a decline DELETES ([`decline`]). The
/// ceiling goes from `1.5 x len` to `1.2 x len + 256 per article`, so
/// it is LOOSER for a small file (a 648-byte PAR2 index posted at 787
/// is 1.214x and only the framing term admits it at all - it is the
/// very case that constant was derived from) and tighter above about
/// 853 bytes of payload per article. A truthful pairing sits near
/// 1.036x plus framing, so 1.2 still leaves an honest rebuild about
/// 16% of slack against real yEnc's 3.6%; what is refused now is the
/// 1.2..1.5 region, where nothing a poster's own tool produces lands
/// and where a FOREIGN rebuild could previously be kept under a real
/// name.
///
/// `segments` is the slot's `total_segments`, which is
/// `f.segments.len() + f.dropped_segments` while the declared byte
/// total sums the listed segments only. A slot with dropped segments
/// therefore buys framing allowance for articles whose bytes are not
/// in `encoded` - the generous direction, on a constant that is
/// already a generous upper bound, and it can only ever KEEP a rebuild
/// this pass would otherwise drop.
fn fits(len: u64, encoded: u64, segments: u64) -> bool {
    crate::get::settle::alias_size_band(encoded, len, segments)
}

/// May a residual rebuild turn this job green?
///
/// The X5-24 ruling's option A: a job that produced every member must
/// report success, and the verdict was counting segments that never
/// arrived for a file a late set had just reconstructed and MD5-proved.
///
/// Conservative in the same four ways
/// [`repair_accounts_for_the_shortfall`] is, because this is the one
/// direction that turns a failure green - `derrs_net` must be zero, the
/// census must not have counted something these slots cannot see, and
/// EVERY short slot must be accounted for - plus the one this pass adds
/// of its own: the account is only ever a rebuild the uniqueness gate
/// above already KEPT, so a declined or ambiguous set can never be the
/// reason a job goes green.
///
/// `denied_unresolved` is the FIFTH, added 1 Sep 2026, and it is W4-01B
/// rather than anything about rebuilds: a VOUCHED set of this job may
/// currently be saying the bytes on disk are not the bytes it describes,
/// and this tier used to test `!good` and nothing else, so it could not
/// tell that denial from the ordinary short download it exists to
/// excuse. A member some other set rebuilt says nothing whatever about
/// the member the denial is about - a swapped payload with truthful
/// yEnc CRCs leaves its slot COMPLETE, so it is in neither `short` nor
/// the census nor `derrs_net`, and every clause above passes.
fn residual_accounts_for_the_shortfall(
    assigned: &[Option<usize>],
    short: &[usize],
    incomplete: usize,
    census_len: usize,
    derrs_net: u64,
    denied_unresolved: bool,
) -> bool {
    !denied_unresolved
        && derrs_net == 0
        && !short.is_empty()
        && incomplete <= census_len
        && assigned.iter().all(Option::is_some)
}

/// The files a VOUCHED late set rebuilt, as chain-tier candidates.
///
/// `files_created` and not `files_patched`, because the tier only ever
/// answers for a slot that delivered NOTHING ([`lost_whole`]) - a file
/// the repair had to CREATE is the only shape such a slot can have on
/// disk. A zero-length creation is skipped for [`residual_creations`]'s
/// reason at its own site: it carries no length to be assigned by.
///
/// No `file_had_bytes_on_disk` filter, and that is the difference from
/// [`residual_creations`] rather than an omission. That filter is X-4's
/// gate on whether a rebuild has EVIDENCE OF ITS OWN that the set
/// belongs where it ran, and it is needed there because the set is
/// vouched for by nothing. Here an ACTIVE set of this job
/// cryptographically names one of this set's packet files, which is the
/// same evidence [`vouched`] looks for and a stronger statement than any
/// per-file adoption could make.
///
/// The length is read at
/// [`nzbkit::par2repair::FileRepair::path`] for [`residual_creations`]'s
/// X-8 reason, `files_created` staying the membership test because that
/// is the question this tier asks. Nothing here DELETES, so a wrong
/// path costs a wrong LENGTH rather than a wrong file: a disambiguated
/// member contributed no candidate at all, and the slot it was the
/// rebuild of went unaccounted for and left the job failed.
///
/// STATED LIMIT, since the population moved from "one candidate per
/// created NAME" to "one per TARGET of a created name". Where a set
/// declares one name TWICE and only one of the two was created, this
/// now offers both. It cannot make a job green that the old shape
/// failed for a good reason - [`assign_by_length`] wants mutual
/// uniqueness, so a second candidate of a length makes the pairing
/// ambiguous rather than decidable - and the old shape was not right
/// there either: it offered ONE candidate at a path it guessed from the
/// name, which on that very set is the path of whichever target won the
/// claim loop and not necessarily the created one. Making it exact
/// wants a per-target "was this created" on the report, which is a
/// second added field and a separate decision.
fn chain_creations(r: &nzbkit::par2repair::RepairReport) -> Vec<Chained> {
    r.per_file
        .iter()
        .filter(|f| r.files_created.contains(&f.name))
        .filter_map(|f| {
            let len = std::fs::metadata(&f.path).map_or(0, |m| m.len());
            (len > 0).then(|| Chained {
                name: f.name.clone(),
                len,
            })
        })
        .collect()
}

/// Which short slot each CHAIN rebuild is, by the same X5-24 rule the
/// residual gate uses - `by_slot[k]` naming the chain candidate that
/// uniquely fits short slot `k`, or `None`.
///
/// Lifted out of [`chain_accounts_for_the_shortfall`] on 1 Sep 2026 so
/// that the ONE table has TWO readers, which is the whole of that
/// finding. [`decide`]'s cross-candidate clause ("more than one leftover
/// set fits the same lost file") can only see the table it was handed,
/// and the two families were built into two tables and asked
/// separately - so a foreign rebuild and a vouched rebuild that fit the
/// SAME lost slot were each unique within their own list and both
/// accepted. The residual was then KEPT under a real name while the
/// chain tier credited the slot, which is exactly the outcome
/// [`keep_uniquely_assignable_residuals`]' own "why the file is deleted
/// rather than left" section exists to prevent: another release's
/// payload in this download's output directory for an *arr to import.
///
/// Deliberately NOT a merge of the two length lists into one table.
/// Merging would make the CHAINED candidate's own verdict ambiguous
/// too, leave the slot unaccounted, and flip a byte-exact chain job from
/// green to red; the veto this table feeds is asymmetric on purpose (see
/// [`keep_uniquely_assignable_residuals`]).
fn chain_assignment(
    chained: &[Chained],
    short: &[usize],
    slot_bytes: &[u64],
    slots: &[Arc<FileSlot>],
) -> Vec<Option<usize>> {
    let lens: Vec<u64> = chained.iter().map(|c| c.len).collect();
    let mut by_slot: Vec<Option<usize>> = vec![None; short.len()];
    for (i, verdict) in assign_by_length(&lens, short, slot_bytes, slots)
        .into_iter()
        .enumerate()
    {
        if let Ok(k) = verdict {
            by_slot[k] = Some(i);
        }
    }
    by_slot
}

/// May a chain rebuild turn this job green?
///
/// `by_slot` is [`chain_assignment`]'s table, computed by the caller so
/// that the residual gate can be asked the same question off the same
/// answer.
///
/// THE ROW: a par2-of-par2 post that delivers every byte still exited
/// NONZERO. Its SIDECAR slots are refused by construction - the inner
/// recovery set is posted under hash names, so the plan gives it payload
/// slots, and the poster never intends those articles to be the route
/// the file arrives by - and the outer set then rebuilds them from
/// parity. The verdict counted the segments that never arrived for files
/// the chain had reconstructed and MD5-proved, which is X5-24's own
/// finding one seam over: measured 31 Aug 2026 on a two-level chain,
/// `movie.bin` landed at 120,000 bytes MD5-proved and the run ended
/// "download incomplete: 6 file(s) with missing segments". A wrong
/// FAILURE verdict on a successful job is the mirror of the wrong-
/// success class this repo treats as its most serious: it tells the user
/// - and every *arr reading the exit code - to fetch again a post that
/// is complete on disk.
///
/// Conservative in exactly the five ways
/// [`residual_accounts_for_the_shortfall`] is, and it is the SAME
/// question with a stronger warrant: no vouched set may currently be
/// denying (W4-01B, and see that function's note on the fifth clause),
/// `derrs_net` must be zero, the census must not have counted something
/// these slots cannot see, and EVERY outstanding slot must be accounted
/// for - by a residual the X5-24 gate already KEPT, or by a chain
/// rebuild [`assign_by_length`] finds uniquely assignable to it in both
/// directions.
///
/// # Why this is safe in the direction that turns a failure green
///
/// The candidate is a file an APPLIED set CREATED from its own parity
/// and MD5-proved, and that set is one an ACTIVE set of this job names a
/// packet file of. So the file is this post's, and its bytes are proven.
/// The only question left is WHICH loss it is, and that is the same
/// decidability test X5-24 settled on - refused outright where two
/// losses fit one rebuild, or two rebuilds fit one loss.
///
/// # What it deliberately cannot do
///
/// It answers only for rebuilds made in THIS pass. A slot whose file was
/// rebuilt by the ACTIVE set's own pre-settle repair is
/// `settle::repair::reconcile_obfuscated_aliases`'s to excuse, and where
/// that pass leaves one starved this tier has no candidate for it and
/// the job stays failed - the safe direction, and a separate row.
///
/// That sentence said "greedy first-fit band" until 31 Aug 2026, which
/// is no longer what starves a slot there: the band now carries an
/// additive per-article yEnc framing allowance and the pairing is global
/// best-fit rather than slot-order first-fit (claim
/// `reconcile-band-and-cross-set-pairing`,
/// `research/RECONCILE-BAND-PAIRING-2026-08-31.md`). The DIVISION is
/// unchanged and is the part that matters here - that pass owns rebuilds
/// its own repair made, this tier owns rebuilds this pass made - so what
/// reaches this tier starved is now a slot no proven member of an active
/// set's own sets fits, rather than one a better-fitting neighbour took
/// the spare from.
#[expect(clippy::too_many_arguments)]
fn chain_accounts_for_the_shortfall(
    assigned: &[Option<usize>],
    by_slot: &[Option<usize>],
    chained: &[Chained],
    short: &[usize],
    slots: &[Arc<FileSlot>],
    incomplete: usize,
    census_len: usize,
    derrs_net: u64,
    denied_unresolved: bool,
) -> bool {
    if denied_unresolved
        || derrs_net > 0
        || short.is_empty()
        || incomplete > census_len
        || chained.is_empty()
    {
        return false;
    }
    if !(0..short.len()).all(|k| assigned[k].is_some() || by_slot[k].is_some()) {
        return false;
    }
    // Said per SLOT and only once the verdict is settled, so the log
    // never claims an identity the gate went on to refuse.
    for (k, &c) in by_slot.iter().enumerate() {
        if let Some(i) = c {
            info!(
                target: "par2",
                "{}: never arrived under its posted name, and a recovery set this \
                 job's own set vouches for rebuilt it as {} ({} bytes, MD5-proved) \
                 - the post admits exactly one loss it can be",
                slots[short[k]].hint,
                chained[i].name,
                chained[i].len,
            );
        }
    }
    true
}

/// Does an ACTIVE set of this job NAME one of this late set's packet
/// files? Then the late set's verdict is this job's own evidence and
/// binds the outcome (W4-01).
///
/// ANY packet, where [`published_here`] wants EVERY nested one, and the
/// two are asking different questions on purpose. That one is a licence
/// to RUN a set whose packets sit somewhere this job did not put them,
/// so one unvouched packet is enough to decline it. This one is about
/// whether an answer counts, and a chain's outer set routinely names
/// the inner INDEX while the volumes ride under their own hashes - so
/// requiring every packet would make the commonest chain shape
/// unauthoritative.
fn vouched(
    out_dir: &Path,
    named: &std::collections::HashSet<String>,
    packets: &[std::path::PathBuf],
) -> bool {
    packets
        .iter()
        .any(|p| named.contains(&nzbkit::disk::out_name_of(out_dir, p).to_lowercase()))
}

/// Which of the sets a census found may vote on a CONTESTED
/// destination name: the ones this pass can actually apply.
///
/// One rule, one copy - the round takes this once and re-takes it
/// whenever a repair creates a packet file, and the two must not come
/// to disagree about what "applicable" means. ACTIVE sets are in: their
/// files are already on disk under the declared name, so contesting
/// against them is exactly right. See the call site for why a set this
/// pass will refuse in every round must not narrow a running set's
/// target away from its declared name (F6, 1 Sep 2026).
fn applicable_ids(
    out_dir: &Path,
    named: &std::collections::HashSet<String>,
    active: &std::collections::HashSet<[u8; 16]>,
    found: &[([u8; 16], Vec<std::path::PathBuf>)],
) -> std::collections::HashSet<[u8; 16]> {
    found
        .iter()
        .filter(|(id, packets)| active.contains(id) || published_here(out_dir, named, packets))
        .map(|(id, _)| *id)
        .collect()
}

/// Did this repair write a file that is itself a PAR2 packet file?
///
/// By MAGIC and not by extension, the way every other packet decision
/// in this tree is made (`par2::head_is_packet_file`): an obfuscated
/// post's recovery volumes carry hash names, and a `.par2` test would
/// miss exactly the shape the nested walk exists for. Reads the head of
/// the files this repair CREATED and nothing else; an unreadable one
/// answers false, which costs a re-census this round and is answered by
/// the next round's own census.
fn created_a_packet_file(r: &nzbkit::par2repair::RepairReport) -> bool {
    use std::io::Read;
    r.per_file
        .iter()
        .filter(|f| r.files_created.contains(&f.name))
        .any(|f| {
            let Ok(mut fh) = std::fs::File::open(&f.path) else {
                return false;
            };
            let mut head = [0u8; nzbkit::par2::SNIFF_WINDOW + 8];
            let n = fh.read(&mut head).unwrap_or(0);
            nzbkit::par2::head_is_packet_file(&head[..n])
        })
}

/// Does this job vouch for where this set's packets are?
///
/// A packet file at the job ROOT is where a recovery set has always
/// been allowed to be, and this pass has always applied one - so those
/// pass unchanged. A packet file BELOW the root only counts when an
/// ACTIVE set names exactly that path, which is what a par2-of-par2
/// chain looks like: the outer set cryptographically identified
/// `META/inner.par2` as part of THIS job, so the inner set's result is
/// authoritative here (W4-01's wording, W4-06's shape).
///
/// Without this, widening discovery would also reach a recovery set an
/// in-stream extraction happened to unpack into a subdirectory - a set
/// whose data files are in THAT directory, not at the root. Repairing
/// it against the root prices every one of its files missing, and at
/// high enough redundancy the repair would go on to CREATE them there:
/// files recreated in a directory that never wanted them. That is the
/// resurrection `repair_present_sets` keeps a name gate to avoid, and
/// the name gate is no use here - the whole point of the late set is
/// that its file is on disk under somebody else's name.
fn published_here(
    out_dir: &Path,
    named: &std::collections::HashSet<String>,
    packets: &[std::path::PathBuf],
) -> bool {
    packets.iter().all(|p| {
        p.parent() == Some(out_dir)
            || named.contains(&nzbkit::disk::out_name_of(out_dir, p).to_lowercase())
    })
}

/// Is there a file here that no ACTIVE recovery set speaks for - the
/// thing a non-activated set would exist to name?
///
/// Tree-aware for the same reason discovery is (W4-06): publication
/// preserves a safe relative path, so the file waiting for its name can
/// legitimately be at `VIDEO_TS/VTS_01_1.VOB`, and a top-level
/// `read_dir` sees a DIRECTORY there rather than an unclaimed file.
/// Names are compared as the `out_dir`-relative output name, which is
/// what the active sets' own `sanitize_out_name` spelling is - a
/// basename comparison would call `META/inner.par2` unclaimed on a job
/// whose outer set names exactly that.
///
/// Widening this makes the door OPEN more often, and since W4-01 that
/// is NOT free - which this comment claimed it was, wrongly, from the
/// hour both landed. F12's pass logged and discarded every verdict, so
/// widening really could only ever add; W4-01's `vouched` rule then
/// made an authoritative late set's DENIAL fail the job, and nothing
/// came back to correct the sentence here. Wave-4 row M4-102 measured
/// what that cost on 31 Aug 2026, on the very arrangement this walk
/// exists to admit: a leftover a directory down armed the door, the
/// vouched set behind it priced its only member wholly missing because
/// `par2repair::adopt`'s candidate scan was still a flat `read_dir`,
/// and a job that had finished rc=0 (hash-named, but finished) before
/// W4-06 failed outright after it. So the two halves are now held
/// together at the call site: `apply_nonactivated_disk_sets` offers
/// this tree's own directories to that scan as adoption donors, via
/// `par2repair::nested_subdirs`, which is DERIVED from the same walk
/// rather than a second one, so the THREE bounds this function carries -
/// depth, directories, entries - are decided in one place for both.
/// Widen this walk and that one follows; widen this walk alone and the
/// failure above is what you get. Deriving is not the same as being
/// identical, and the difference bit once already: `walk_candidates`
/// carries a FOURTH bound, a cumulative byte budget on what a packet
/// walk might LOAD, which this function has no equivalent of - charged
/// against the donor list it made the reach fall short of the door on
/// an ordinary season pack. `nested_subdirs`' own doc has the
/// measurement. If a bound is added HERE, check that one's list too. The foreign-set decoy row is untouched either way: an
/// unvouched set still cannot fail a job.
///
/// Symlinks are skipped and never followed - a `DirEntry`'s own file
/// type is an `lstat`, so a symlinked directory is neither `is_dir()`
/// nor `is_file()` - and the walk is bounded by the same shape
/// `par2repair::nested` uses: depth, directories, entries. It stops at
/// the FIRST unclaimed file, so the budgets only bind on a directory
/// that has nothing to find.
fn has_unclaimed(out_dir: &Path, named: &std::collections::HashSet<String>) -> bool {
    const MAX_DEPTH: usize = 6;
    const MAX_DIRS: usize = 512;
    const MAX_ENTRIES: usize = 100_000;
    let mut queue: std::collections::VecDeque<(std::path::PathBuf, usize)> =
        std::collections::VecDeque::new();
    queue.push_back((out_dir.to_path_buf(), 0));
    let mut dirs = 0usize;
    let mut entries = 0usize;
    while let Some((d, depth)) = queue.pop_front() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        dirs += 1;
        for e in rd.flatten() {
            entries += 1;
            if entries > MAX_ENTRIES {
                return false;
            }
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                if depth < MAX_DEPTH && dirs + queue.len() < MAX_DIRS {
                    queue.push_back((e.path(), depth + 1));
                }
                continue;
            }
            if !ft.is_file() {
                continue;
            }
            let rel = nzbkit::disk::out_name_of(out_dir, &e.path()).to_lowercase();
            let leaf = e.file_name().to_string_lossy().to_lowercase();
            if leaf.starts_with('.') || named.contains(&rel) {
                continue;
            }
            if leaf.ends_with(".par2") && has_par2_magic(&e.path()) {
                continue;
            }
            return true;
        }
    }
    false
}

/// Wave-4 row M4-52 (30 Aug 2026): the `.par2` skip above is a NAME
/// test, and this asks the file whether the name is telling the truth.
///
/// The skip is right about recovery data - a spent volume is nobody's
/// unclaimed payload - and wrong about a payload WEARING that
/// extension, which is what the composition of M4-28 posts: the
/// obfuscated payload's yEnc `name=` is `<hash>.par2`, so it lands
/// under that name, the inner set that would have called it
/// `movie.mkv` never activated, and this door reported nothing
/// unclaimed. The late pass never ran and the job finished clean over
/// a payload still wearing a hash.
///
/// The house rule (`wave4-fix-exact-name-authority`, 2b7f5495e) is
/// that a NAME may nominate and only CONTENT may finalize. Eight bytes
/// is the WEAKEST disqualifier available and that is deliberate: a
/// file that does not even open with the packet magic is not recovery
/// data under any reading, so treating it as unclaimed is not a
/// judgement call. THAT LAST CLAUSE IS NO LONGER TRUE and the
/// paragraph is kept for its lineage rather than its rule - row M4-65
/// made the window the weakest disqualifier, and the note below it
/// carries what replaced this. Nothing stronger belongs here, because since W4-01
/// a vouched late set can take a job's success AWAY - the module note
/// above says opening this door wider is a real change and not a free
/// one - so it opens on the least evidence that settles the question
/// and no more. The sibling row M4-53 asks the mirror question one
/// seam over and gets the opposite answer for the same reason: see
/// `nzbkit::par2repair::is_recovery_volume_shape`, where the action is
/// DELETION and nothing short of complete evidence will do.
///
/// Unreadable reads as recovery data - the historical behaviour of the
/// name test, and the direction that changes no verdict.
///
/// THE WINDOW, NOT BYTE 0, since 31 Aug 2026 - and the sentence above
/// about eight bytes being the weakest disqualifier available was made
/// FALSE by row M4-65 before this line moved. That row widened the
/// product's content sniff to "the magic BEGINS within
/// [`nzbkit::par2::SNIFF_WINDOW`] bytes", because a volume behind a
/// short prefix - a UTF-8 BOM from a producer that touched it as text -
/// is still the post's parity. So "does not even open with the packet
/// magic" stopped meaning "not recovery data under any reading" the day
/// that landed, and the weakest disqualifier is now the window. Reading
/// it any other way is not caution, it is a second rule.
///
/// MEASURED, on one directory holding a BOM-prefixed but otherwise
/// ordinary volume and the file it covers. Four readers, one file:
/// [`nzbkit::par2::head_is_packet_file`] says packet file,
/// `nzbkit::par2::Par2Set::parse` returns a set of one,
/// `nzbkit::par2repair::disk_sets_scoped` - the discovery
/// [`apply_nonactivated_disk_sets`] runs on the very NEXT statement
/// after this door - lists that path under its set id, and this
/// function alone called it unclaimed payload. That is not M4-65's
/// doing either: `par2repair::collect_packet_files` takes a `.par2`
/// name as a packet file unconditionally and always has, and
/// `par2::scan_packets` walks the WHOLE buffer for magic, so a prefixed
/// volume has always been fully functional recovery data everywhere
/// except here. The door opened on the pass's own parity.
///
/// WHICH DIRECTION IS CONSERVATIVE HERE IS THE OPPOSITE OF THE SWEEP,
/// and it is the one thing to get straight before touching this again.
/// Widening makes this answer TRUE for more files, so more files are
/// SKIPPED, so [`has_unclaimed`] opens LESS often - which is the
/// direction the module note protects, because since W4-01 a vouched
/// late set can take a job's success away. At `is_recovery_volume_shape`
/// the action is DELETION, so widening there made the product delete
/// MORE and had to be bought with complete evidence (M4-53). Same
/// entry point, opposite actions, and the asymmetry of EVIDENCE is
/// unchanged: what moved is where the read starts, never what the
/// answer licenses.
///
/// It is a PURE widening, deliberately. Every file skipped before is
/// skipped now, and nothing newly opens the door - which is why a file
/// with fewer than `MAGIC.len()` bytes still reads as recovery data:
/// `read_exact` of eight bytes used to FAIL on one, so it fell into the
/// unreadable arm, and a file too short to carry the magic can no more
/// be shown NOT to be parity than an unopenable one can.
///
/// The M4-52 payload it exists to catch is untouched: an obfuscated
/// `<hash>.par2` whose first 72 bytes happen to contain `PAR2\0PKT`
/// would now be skipped, at roughly 2^-58 for a file nobody chose those
/// bytes for, against a prefixed volume this reported wrongly every
/// time.
///
/// `nzbkit::par2repair::adopt`'s `is_recovery_by_name_and_content` is
/// the SAME M4-52 predicate at the donor seam and is still at byte 0.
/// It was left alone on purpose - there the answer gates whether a
/// candidate may be an adoption SOURCE, which is a different action
/// with three open claims on it - so a lane finding two spellings of
/// one row should read that seam's own direction before folding them
/// together, never assume this one settles it.
fn has_par2_magic(path: &Path) -> bool {
    use std::io::Read as _;
    const WANT: usize = nzbkit::par2::SNIFF_WINDOW + 8;
    let mut head: Vec<u8> = Vec::with_capacity(WANT);
    match std::fs::File::open(path).and_then(|f| f.take(WANT as u64).read_to_end(&mut head)) {
        Ok(n) if n < nzbkit::par2::MAGIC.len() => true,
        Ok(_) => nzbkit::par2::head_is_packet_file(&head),
        Err(_) => true,
    }
}

/// Slots this job never finished downloading - the same test the
/// census counts `incomplete` with (`get::census`), so the two agree
/// about what is outstanding.
fn incomplete_slots(slots: &[Arc<FileSlot>]) -> Vec<usize> {
    (0..slots.len())
        .filter(|&i| {
            slots[i].missing.load(Ordering::Relaxed) > 0
                || slots[i].remaining.load(Ordering::Relaxed) > 0
        })
        .collect()
}

/// Whether a vouched late set's repair accounts for EVERYTHING that was
/// outstanding, so the job may report success after all - and, when it
/// does, the superseded partials the caller should sweep once the whole
/// pass is done (`None` means it does not account, and nothing is
/// deletable on that basis).
///
/// The evidence is the repair's own report, and `Repaired` is a strong
/// statement: every patched file was MD5-re-verified off disk before
/// the status was returned. So a short slot is accounted for when its
/// partial file is where those proven bytes CAME FROM - swept outright
/// as a spent source, or named in `adopted_from` with a proven file of
/// exactly its length beside it. The partial is then a strictly worse
/// copy of a file the set has proved whole, and goes through the same
/// recoverable sweep an adopted source does.
///
/// Deliberately conservative in four ways, because this is the one
/// direction that turns a failure green:
///
/// * `derrs_net` must be zero - a decode or write error is not a
///   shortfall a recovery set can speak to, and the caller has already
///   subtracted the metadata the spare rule forgives.
/// * EVERY short slot must be accounted for. One that the repair never
///   read is still missing bytes nothing has proven.
/// * the length test is what stops a lone shared block deciding it. A
///   holed file is written at full length with a hole in it, so an
///   unrelated short slot that happened to donate one zero block to
///   the target adopts without matching its length.
/// * `incomplete` must not exceed the slots this pass can see, so a
///   census that counted something else - the sparse-coverage arm,
///   which leaves both slot counters at zero - still fails the job.
///   The reverse skew (spared metadata, counted here and not there)
///   simply leaves the job failing, which is the safe side of it.
///   `census_len` and not `short.len()`, since the chain row: `short`
///   is what is still OUTSTANDING, which on a par2-of-par2 post is a
///   strict subset of what the census counted, and comparing the two
///   asks the sparse question of the wrong population - see
///   [`Outstanding`]'s fifth field.
#[expect(clippy::too_many_arguments)]
fn repair_accounts_for_the_shortfall(
    r: &nzbkit::par2repair::RepairReport,
    short: &[usize],
    slots: &[Arc<FileSlot>],
    extractor: &Arc<nzbkit::extract::Extractor>,
    out_dir: &Path,
    incomplete: usize,
    census_len: usize,
    derrs_net: u64,
) -> Option<Vec<PathBuf>> {
    if derrs_net > 0 || short.is_empty() || incomplete > census_len {
        return None;
    }
    // Lengths read at the path the repair LANDED each target at (X-8),
    // never at one rebuilt from the reported name: a target the engine
    // had to disambiguate is at `<name>.dup-<fid>`, so a name-derived
    // stat contributes another target's length or none at all. The
    // population is still the names the repair says it touched -
    // `per_file` covers every target of the set, damaged or not, and an
    // untouched one's length is nothing this test may lean on.
    //
    // Same stated limit as [`chain_creations`]: one entry per TARGET of
    // a touched name rather than one per touched name, so a set
    // declaring one name twice with only one of the two touched
    // contributes an extra length here. It only ever LOOSENS a test
    // that already needs `adopted_from` to name the partial as well,
    // and the shape it differs on is the shape where the name-derived
    // stat was reading somebody else's file to begin with.
    let touched: std::collections::HashSet<&str> = r
        .files_patched
        .iter()
        .chain(&r.files_created)
        .map(String::as_str)
        .collect();
    let proved: Vec<u64> = r
        .per_file
        .iter()
        .filter(|f| touched.contains(f.name.as_str()))
        .filter_map(|f| std::fs::metadata(&f.path).ok())
        .map(|m| m.len())
        .collect();
    let consumed: std::collections::HashSet<&Path> =
        r.consumed_sources.iter().map(PathBuf::as_path).collect();
    let mut redundant: Vec<PathBuf> = Vec::new();
    for &s in short {
        let p = extractor.slot_path(s).unwrap_or_else(|| {
            nzbkit::disk::join_out_name(out_dir, &nzbkit::disk::sanitize_out_name(&slots[s].hint))
        });
        // OUT-RELATIVE on both sides since X6-02c (31 Aug 2026), and
        // this is STRICTER than the basename compare it replaces, in
        // the two directions that matter here.
        //
        // `adopted_from` used to be `file_name()`, so on a tree
        // `disc1/x.vob` and `disc2/x.vob` were one entry - a short slot
        // could be credited to a SIBLING's partial - and a candidate
        // from a DONOR directory carried a bare leaf that could collide
        // with a short slot's and credit it with somebody else's file.
        // Both are gone: the engine names its own tree out-relative and
        // marks a donor, so a donor entry can equal no slot path and a
        // tree member matches only itself.
        //
        // Strictly-fewer greens is the right direction for this test in
        // particular - it is the one rule here that turns a failed job
        // into a successful one - and nothing legitimate is lost: a
        // short slot's file is inside the job directory by construction,
        // so its evidence was never a donor's, and a FLAT job's
        // out-relative name IS its basename, which is every post that
        // passed this before trees existed.
        let leaf = nzbkit::disk::out_name_of(out_dir, &p);
        let adopted = r.adopted_from.iter().any(|a| a.as_str() == leaf)
            && std::fs::metadata(&p).is_ok_and(|m| proved.contains(&m.len()));
        if !consumed.contains(p.as_path()) {
            if !adopted {
                return None;
            }
            redundant.push(p);
        }
        info!(
            target: "par2",
            "{}: the short download is accounted for - a recovery set this job's own \
             set vouches for rebuilt and MD5-proved its bytes under their real name",
            slots[s].hint
        );
    }
    // HANDED BACK rather than swept here, since X5-10 (31 Aug 2026).
    // These are this job's own superseded partials, and the reasoning
    // that makes them deletable is per-slot rather than per-set - but
    // the late-set pass is a fixpoint now, so another set two rounds on
    // may still read a partial as an adoption source. One rule for the
    // whole pass is cheaper to keep true than two: nothing goes until
    // every set has spoken.
    Some(redundant)
}

/// NZB file indexes with no slot at all - which, by the plan's own
/// rule ("slots skip NZB-classified volumes"), is exactly the posted
/// recovery data nothing has fetched yet. Finding F11's other half:
/// on the set-less settle path these are the only place a damaged
/// index's file list still exists, so a clean-looking job must fetch
/// them before the disk pass can name anything.
pub(super) fn unfetched_recovery_files(nzb: &Nzb, slot_file: &[usize]) -> Vec<usize> {
    let slotted: std::collections::HashSet<usize> = slot_file.iter().copied().collect();
    (0..nzb.files.len())
        .filter(|i| !slotted.contains(i))
        .collect()
}

#[cfg(test)]
mod shape_tests;

#[cfg(test)]
mod par2_window_tests;

// X5-13: cancellation during the late recovery-set pass - the work
// bound, and the latch's polarity. Its own file, one subject per file.
#[cfg(test)]
mod cancel_tests;

#[cfg(test)]
mod tests {
    use super::{
        Chained, Residual, assign_by_length, chain_accounts_for_the_shortfall, decide, fits,
    };
    use super::{FileSlot, has_unclaimed};
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    /// A slot that delivered `missing` of `total` segments.
    fn slot(hint: &str, total: usize, missing: usize) -> Arc<FileSlot> {
        Arc::new(FileSlot {
            hint: hint.into(),
            hint_is_posted_name: true,
            yenc_votes: Default::default(),
            name_choice: std::sync::atomic::AtomicU8::new(crate::unpack::NAME_UNDECIDED),
            is_par2_main: false,
            sample_skipped: false,
            par2_name_demoted: Default::default(),
            par2_sniffed: AtomicBool::new(false),
            total_segments: total,
            remaining: AtomicUsize::new(0),
            missing: AtomicUsize::new(missing),
            errors: AtomicUsize::new(0),
            deferred: AtomicUsize::new(0),
            abandoned: AtomicUsize::new(0),
            capture: std::sync::Mutex::new(None),
        })
    }

    /// X6-02c's CONSUMER half (claim `x6-02c-adopted-from-tree-path`,
    /// 31 Aug 2026), and the reason both halves had to move in one
    /// commit: this is one of the few rules in the tree that turns a
    /// FAILED job green, and it matched a short slot's BASENAME against
    /// `adopted_from`.
    ///
    /// Three arms, and the middle one is the whole row. A flat job is
    /// unchanged (an out-relative name IS a basename there), a tree
    /// member is credited only by its OWN entry rather than by a
    /// same-leaf sibling's, and a DONOR's marked entry credits nothing -
    /// under the basename spelling a donor's leaf could collide with a
    /// short slot's and buy the job a green on somebody else's file.
    #[test]
    fn a_short_slot_is_credited_only_by_an_entry_naming_its_own_place() {
        use nzbkit::par2repair::{FileRepair, RepairReport};
        let d = tmp("shortfall-names");
        std::fs::create_dir_all(d.join("disc1")).unwrap();
        std::fs::create_dir_all(d.join("disc2")).unwrap();
        // The short slot's own partial, one directory down, and a
        // same-leaf file in the SIBLING directory beside it.
        std::fs::write(d.join("disc1").join("x.vob"), vec![3u8; 400]).unwrap();
        std::fs::write(d.join("disc2").join("x.vob"), vec![4u8; 400]).unwrap();
        // The repair's proved target, at the length the partial has to
        // match for the length arm to pass.
        std::fs::write(d.join("proved.vob"), vec![9u8; 400]).unwrap();

        let ex = Arc::new(nzbkit::extract::Extractor::new(&d, 1, false));
        ex.anchor();
        let slots = [slot("disc1/x.vob", 4, 1)];
        let report = |from: Vec<String>| RepairReport {
            blocks_rebuilt: 0,
            blocks_adopted: 1,
            adopted_from: from,
            files_patched: vec!["proved.vob".to_string()],
            files_created: Vec::new(),
            consumed_sources: Vec::new(),
            per_file: vec![FileRepair {
                name: "proved.vob".to_string(),
                blocks_rebuilt: 0,
                blocks_adopted: 1,
                path: d.join("proved.vob"),
            }],
        };
        let ask = |from: Vec<String>| {
            super::repair_accounts_for_the_shortfall(&report(from), &[0], &slots, &ex, &d, 1, 1, 0)
        };

        assert!(
            ask(vec!["disc1/x.vob".to_string()]).is_some(),
            "its own out-relative entry is what accounts for it"
        );
        assert!(
            ask(vec!["disc2/x.vob".to_string()]).is_none(),
            "a same-leaf file in a SIBLING directory is not this slot's evidence"
        );
        // The donor form, spelled out rather than imported: the marker
        // is `nzbkit::par2repair::adopt`'s and is pinned there. What is
        // asserted HERE is only the property this side depends on - an
        // entry that is not this slot's own out-relative name credits
        // nothing - so a change to the marker's wording cannot make
        // this pass for the wrong reason.
        assert!(
            ask(vec!["x.vob (donor directory)".to_string()]).is_none(),
            "and a donor's file is never a short slot's own partial"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    fn chained(names_and_lens: &[(&str, u64)]) -> Vec<Chained> {
        names_and_lens
            .iter()
            .map(|(n, len)| Chained {
                name: (*n).to_string(),
                len: *len,
            })
            .collect()
    }

    /// The rule both tiers share, driven directly. A rebuild is the loss
    /// it uniquely fits; a slot that received SOME bytes is never a
    /// candidate at all, however well the length agrees, because the
    /// ruling is about a member lost WHOLE.
    #[test]
    fn a_rebuild_is_assigned_only_to_a_whole_loss_it_uniquely_fits() {
        let slots = [slot("a", 2, 2), slot("b", 2, 2), slot("part", 2, 1)];
        let bytes = [124_000u64, 20_700, 124_000];
        let short = [0usize, 1, 2];
        // 120,000 rebuilt fits slot 0's 124,000 declared - and slot 2
        // declares exactly the same, but it is not a whole loss.
        assert_eq!(
            assign_by_length(&[120_000], &short, &bytes, &slots),
            vec![Ok(0)]
        );
        // Two whole losses of the same size: undecidable, both ways.
        let twins = [slot("a", 2, 2), slot("b", 2, 2)];
        let twin_bytes = [124_000u64, 124_000];
        assert!(
            assign_by_length(&[120_000], &[0, 1], &twin_bytes, &twins)[0]
                .is_err_and(|w| w.contains("more than one whole file")),
        );
        // One loss, two rebuilds that both fit it: undecidable too.
        assert!(
            assign_by_length(&[120_000, 121_000], &[0], &[124_000], &[slot("a", 2, 2)])
                .iter()
                .all(|d| d.is_err()),
        );
    }

    /// The chain tier's four refusals, each on its own. This is the one
    /// direction that turns a failure green, so every one of them has to
    /// bite alone - a version that only refuses when several hold at
    /// once is a version that greens a genuinely short post.
    #[test]
    fn the_chain_tier_refuses_every_way_it_is_meant_to() {
        let slots = [slot("a", 2, 2), slot("b", 2, 2)];
        let bytes = [124_000u64, 20_700];
        let short = [0usize, 1];
        let both = chained(&[("movie.bin", 120_000), ("notes.bin", 20_000)]);
        let none = [None, None];
        let ok = |c: &[Chained], sh: &[usize], inc, census, derrs| {
            let by_slot = super::chain_assignment(c, sh, &bytes, &slots);
            chain_accounts_for_the_shortfall(
                &none, &by_slot, c, sh, &slots, inc, census, derrs, false,
            )
        };
        assert!(ok(&both, &short, 2, 2, 0), "the honest case");
        assert!(!ok(&both, &short, 2, 2, 1), "a decode/write error refuses");
        assert!(!ok(&both, &[], 0, 2, 0), "nothing outstanding refuses");
        assert!(
            !ok(&both, &short, 3, 2, 0),
            "a census counting more than these slots can see refuses"
        );
        assert!(!ok(&[], &short, 2, 2, 0), "no rebuild at all refuses");
        // The row's own shape: one loss covered, one genuinely lost.
        assert!(
            !ok(&both[..1], &short, 2, 2, 0),
            "a slot with no rebuild of its size refuses"
        );
        // W4-01B's fifth refusal (1 Sep 2026): every clause above may
        // pass and a VOUCHED set still be saying, of some OTHER member,
        // that the bytes on disk are not the bytes it describes.
        let by_slot = super::chain_assignment(&both, &short, &bytes, &slots);
        assert!(
            !chain_accounts_for_the_shortfall(
                &none, &by_slot, &both, &short, &slots, 2, 2, 0, true
            ),
            "an unresolved vouched denial refuses whatever the rebuilds account for"
        );
    }

    /// W4-01B, re-closed 1 Sep 2026: a vouched set's DENIAL is not
    /// erased by another set's rebuilds.
    ///
    /// The shape is compound and that is why it survived the original
    /// fix. The denial-only job was always refused and still is - a job
    /// whose only fault is a denial has nothing outstanding, so `short`
    /// is empty and both tiers decline on that alone. Give it a second,
    /// independent fault - one whole-file loss that a late set's
    /// rebuilds uniquely account for - and every clause the tiers test
    /// passes: the denied member's own slot is COMPLETE (a swapped
    /// payload with truthful yEnc CRCs decodes without error), so it is
    /// in neither `short` nor the census nor `derrs_net`. The tiers used
    /// to read `!good` and nothing else, so they flipped the denial's
    /// `good = false` back to true and cleared the shortfall with it.
    ///
    /// Both tiers, because either one alone is enough to green a job.
    #[test]
    fn a_vouched_denial_is_not_erased_by_another_sets_rebuilds() {
        let slots = [slot("a", 2, 2)];
        let bytes = [124_000u64];
        let short = [0usize];
        let chain = chained(&[("movie.bin", 120_000)]);
        let by_slot = super::chain_assignment(&chain, &short, &bytes, &slots);
        let kept = [Some(0usize)];

        // The control: with nothing denying, both tiers green this job.
        assert!(
            super::residual_accounts_for_the_shortfall(&kept, &short, 1, 1, 0, false),
            "the residual tier greens a fully accounted shortfall"
        );
        assert!(
            chain_accounts_for_the_shortfall(
                &[None],
                &by_slot,
                &chain,
                &short,
                &slots,
                1,
                1,
                0,
                false
            ),
            "and so does the chain tier"
        );
        // The row: an authoritative set is still denying, so neither may.
        assert!(
            !super::residual_accounts_for_the_shortfall(&kept, &short, 1, 1, 0, true),
            "the residual tier must not erase a vouched set's denial"
        );
        assert!(
            !chain_accounts_for_the_shortfall(
                &[None],
                &by_slot,
                &chain,
                &short,
                &slots,
                1,
                1,
                0,
                true
            ),
            "and neither may the chain tier"
        );
    }

    /// A residual the X5-24 gate already kept covers its slot, and the
    /// chain tier only has to speak for the rest - so the two tiers add
    /// up rather than each needing to carry the whole shortfall alone.
    #[test]
    fn the_two_tiers_together_cover_the_shortfall() {
        let slots = [slot("a", 2, 2), slot("b", 2, 2)];
        let bytes = [124_000u64, 20_700];
        let short = [0usize, 1];
        let chain = chained(&[("notes.bin", 20_000)]);
        let by_slot = super::chain_assignment(&chain, &short, &bytes, &slots);
        assert!(
            !chain_accounts_for_the_shortfall(
                &[None, None],
                &by_slot,
                &chain,
                &short,
                &slots,
                2,
                2,
                0,
                false
            ),
            "slot a is unaccounted"
        );
        assert!(
            chain_accounts_for_the_shortfall(
                &[Some(0), None],
                &by_slot,
                &chain,
                &short,
                &slots,
                2,
                2,
                0,
                false
            ),
            "a residual the uniqueness gate kept accounts for slot a"
        );
    }

    /// X5-24's band, from both ends - and since 31 Aug 2026 it is
    /// `settle::repair::alias_size_band`'s body rather than this
    /// module's own. Kept HERE as well as beside that function because
    /// what is pinned is this caller's contract: the two numbers are
    /// different measurements (the NZB declares yEnc-ENCODED article
    /// sizes, the rebuilt file is the decoded payload), so it can never
    /// be an equality, and a zero on either side is refused rather than
    /// matching everything - which is what an unslotted or
    /// segment-less file would otherwise do.
    ///
    /// THE THIRD ARGUMENT IS THE WHOLE POINT and the reason the old
    /// pins moved. yEnc's cost is a proportional payload part PLUS a
    /// constant per-article framing part, and a ratio cannot model the
    /// second: the fixture's 648-byte PAR2 index is declared at 787
    /// (1.214x) and only the framing term admits it. The old flat
    /// 0.9..1.5 ratio admitted it too, by being loose enough to admit
    /// a great deal else - which is the pairing this test now pins
    /// from the other side.
    #[test]
    fn the_length_band_admits_yenc_overhead_and_refuses_a_foreign_size() {
        assert!(fits(180_000, 186_338, 1), "the measured honest pairing");
        assert!(!fits(90_000, 186_338, 1), "the measured foreign pairing");
        assert!(fits(1000, 1000, 1), "no overhead at all is still a fit");
        // 1.2 x 1000 + 256 x 1, which is the shared band's own arithmetic.
        assert!(fits(1000, 1456, 1), "the ratio plus one article of framing");
        assert!(!fits(1000, 1457, 1), "and one byte past it is not");
        assert!(fits(1000, 900, 1), "10% of under-declaration is tolerated");
        assert!(!fits(1000, 899, 1), "and one byte past that is not");
        assert!(
            !fits(0, 1000, 1) && !fits(1000, 0, 1),
            "a zero fits nothing"
        );
        // A small member needs the framing term and a ratio alone
        // refuses it: the PAR2 index of the three-level chain fixture.
        assert!(fits(648, 787, 1), "the 648-byte index at its posted 787");
        // THE ROW. Measured 31 Aug 2026 on that same fixture: the
        // rebuilt `setc.vol03+4.par2` is 42,008 bytes and the NEXT
        // volume up declares 53,947 over two articles - a ratio of
        // 1.284, which no encoding produces. The old 0.9..1.5 ratio
        // admitted it, so two of five sidecar slots were undecidable
        // and `chain_accounts_for_the_shortfall` declined on a job
        // that had delivered every byte byte-exact.
        assert!(fits(42_008, 43_587, 2), "the rebuild against its OWN slot");
        assert!(
            !fits(42_008, 53_947, 2),
            "and not against the next volume up, which is what made the \
             deepest chain fixture undecidable"
        );
        assert!(
            fits(52_076, 53_947, 2),
            "that slot's own rebuild still fits"
        );
    }

    /// The uniqueness rule, both directions, driven over the fit table
    /// alone. The second direction is the one no e2e fixture reaches:
    /// two leftover sets whose rebuilds fit the SAME single loss, which
    /// is decidable for neither of them however unique each looks from
    /// its own side.
    #[test]
    fn an_assignment_is_kept_only_when_it_is_unique_in_both_directions() {
        // One rebuild, one loss it can be.
        assert_eq!(decide(&[vec![0]], 0), Ok(0));
        // Nothing fits: the foreign-set control.
        assert!(decide(&[vec![]], 0).is_err_and(|w| w.contains("no whole file")));
        // Two losses fit one rebuild: the ambiguous control.
        assert!(decide(&[vec![0, 1]], 0).is_err_and(|w| w.contains("more than one whole file")));
        // One loss fits, but a second rebuild fits it too - so neither
        // may take it, and the answer must not depend on which set the
        // packet arrival order put first.
        let both = [vec![0], vec![0]];
        assert!(decide(&both, 0).is_err_and(|w| w.contains("more than one leftover set")));
        assert!(decide(&both, 1).is_err_and(|w| w.contains("more than one leftover set")));
        // A second rebuild that fits a DIFFERENT loss takes nothing
        // away from the first.
        let apart = [vec![0], vec![1]];
        assert_eq!(decide(&apart, 0), Ok(0));
        assert_eq!(decide(&apart, 1), Ok(1));
    }

    /// The CROSS-FAMILY veto (1 Sep 2026). [`super::decide`]'s
    /// "more than one leftover set fits the same lost file" clause can
    /// only see the table it was handed, and the residual family and the
    /// chain family were built into two tables and asked separately - so
    /// one lost slot could be a foreign rebuild's unique fit AND a
    /// vouched rebuild's, and both were accepted. The chain tier then
    /// credited the slot while the foreign file stayed in the output
    /// directory under a real name, which is what an *arr imports.
    ///
    /// Graded on all three consequences, because fixing only the verdict
    /// would leave the file: the assignment is refused, the file is
    /// gone, and the job still greens through the tier that owns the
    /// slot.
    #[test]
    fn a_foreign_rebuild_is_declined_where_a_vouched_one_already_fits_the_slot() {
        let d = tmp("cross-family");
        let foreign = d.join("Not.Ours.bin");
        std::fs::write(&foreign, vec![7u8; 1000]).unwrap();
        let slots = [slot("movie.bin", 1, 1)];
        let bytes = [1000u64];
        let short = [0usize];
        let residual = vec![Residual {
            name: "Not.Ours.bin".to_string(),
            path: foreign.clone(),
            len: 1000,
        }];
        let chain = chained(&[("movie.bin", 1000)]);
        let by_slot = super::chain_assignment(&chain, &short, &bytes, &slots);
        assert_eq!(by_slot, vec![Some(0)], "the vouched rebuild is that loss");

        let assigned =
            super::keep_uniquely_assignable_residuals(&residual, &by_slot, &short, &bytes, &slots);
        assert_eq!(assigned, vec![None], "so the foreign rebuild cannot be");
        assert!(
            !foreign.exists(),
            "and it is dropped rather than left in the output directory under a real name"
        );
        // The veto is asymmetric and costs no green: the slot is still
        // accounted for, by the set that vouched for it.
        assert!(
            chain_accounts_for_the_shortfall(
                &assigned, &by_slot, &chain, &short, &slots, 1, 1, 0, false
            ),
            "the chain tier still covers the slot it vetoed the residual over"
        );

        // The control, so a veto that fired on everything would be seen:
        // with no vouched rebuild for that slot the foreign one is kept
        // and assigned exactly as it was before this rule existed.
        std::fs::write(&foreign, vec![7u8; 1000]).unwrap();
        let assigned =
            super::keep_uniquely_assignable_residuals(&residual, &[None], &short, &bytes, &slots);
        assert_eq!(assigned, vec![Some(0)], "nothing else fits, so it is kept");
        assert!(foreign.exists(), "and the file stays");
        let _ = std::fs::remove_dir_all(&d);
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("nzbfast-lateset-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("mkdir");
        d
    }

    /// X-5's load-bearing invariant, re-read at the per-TARGET
    /// granularity X-4 gave it, and the reason [`super::lost_whole`]
    /// may stay as narrow as it is: a residual is only ever produced
    /// for a member the repair had NO tie to any byte of, anywhere on
    /// this disk. The doc section on
    /// `keep_uniquely_assignable_residuals` leans on that to say why a
    /// partial slot is not the adopted-source case, so loosening any
    /// arm here retires that argument silently.
    ///
    /// X-4 (31 Aug 2026) narrowed the invariant from the REPORT to the
    /// TARGET, and this test was written against the report-wide form:
    /// its three "a tie disqualifies everything" cases said, in as many
    /// words, that one adopted block "disqualifies the WHOLE report
    /// rather than that one member". That is exactly what changed, and
    /// what a leftover set was buying its wholly-missing member with -
    /// so the cases are kept, each converted to the evidence it is
    /// really about, and the two that flip flip HERE where the reason
    /// is written down rather than by being deleted.
    ///
    /// The zero-length arm is X-6, unchanged in either direction by
    /// X-4: such a creation is neither assigned nor deleted, and the
    /// file stays where the repair put it.
    #[test]
    fn a_repair_with_a_tie_to_disk_produces_no_residual_for_that_member() {
        use super::residual_creations;
        use nzbkit::par2repair::{FileRepair, RepairReport};
        let d = tmp("residual");
        std::fs::write(d.join("m.bin"), vec![7u8; 1000]).unwrap();
        std::fs::write(d.join("z.bin"), b"").unwrap();
        // The census's own path, which is what `residual_creations`
        // reads since X-8 - here it is the plain join, since nothing in
        // this test collides. The disambiguated shape is graded end to
        // end by `e2e_lateset::x8_*` and at the engine by
        // `nzbkit`'s `par2repair_namepath`.
        let fr = |n: &str, rebuilt: usize, adopted: usize| FileRepair {
            name: n.to_string(),
            blocks_rebuilt: rebuilt,
            blocks_adopted: adopted,
            path: d.join(n),
        };
        let base = || RepairReport {
            blocks_rebuilt: 8,
            blocks_adopted: 0,
            adopted_from: Vec::new(),
            files_patched: vec!["m.bin".to_string()],
            files_created: vec!["m.bin".to_string()],
            consumed_sources: Vec::new(),
            per_file: vec![fr("m.bin", 8, 0)],
        };
        // Parity alone, no byte of it anywhere here: the residual case.
        let only = residual_creations(&base());
        assert_eq!(only.len(), 1);
        assert_eq!((only[0].name.as_str(), only[0].len), ("m.bin", 1000));

        // One adopted block of THIS member, from anything on disk, is
        // the tie - and it is the case X-5's first reason turns on,
        // because a partial of `m.bin` is what adoption would have
        // found it in.
        let mut r = base();
        r.blocks_adopted = 1;
        r.adopted_from = vec!["frag".to_string()];
        r.per_file = vec![fr("m.bin", 7, 1)];
        assert!(
            residual_creations(&r).is_empty(),
            "a block of this member was adopted"
        );

        // X-4, and the assertion that flips: the same adopted block
        // belonging to a SIBLING says nothing about `m.bin`. This used
        // to disqualify the whole report, which is how a leftover
        // release's wholly-missing member reached the output directory
        // ungated.
        let mut r = base();
        r.blocks_adopted = 1;
        r.adopted_from = vec!["frag".to_string()];
        r.files_patched.push("s.bin".to_string());
        r.per_file = vec![fr("m.bin", 8, 0), fr("s.bin", 0, 1)];
        let still = residual_creations(&r);
        assert_eq!(
            still.len(),
            1,
            "a SIBLING's donor is not this member's evidence"
        );
        assert_eq!(still[0].name.as_str(), "m.bin");

        // A consumed source is a donor that fed SOME target, so on its
        // own it is the same credit-by-sibling: it no longer speaks for
        // `m.bin`, whose own census says it adopted nothing.
        let mut r = base();
        r.consumed_sources = vec![d.join("frag")];
        assert_eq!(
            residual_creations(&r).len(),
            1,
            "a consumed source names no member, so it excuses none"
        );

        // And patching a file that was already here is that FILE's
        // evidence. `m.bin` is in files_created, so it had no bytes on
        // disk to be patched - it cannot borrow `n.bin`'s.
        let mut r = base();
        r.files_patched.push("n.bin".to_string());
        r.per_file.push(fr("n.bin", 1, 0));
        assert_eq!(
            residual_creations(&r).len(),
            1,
            "a resident sibling being patched is not this member's tie"
        );

        // The other side of that: `m.bin` NOT created at all means it
        // was on disk when the repair began, which is a tie of its own.
        let mut r = base();
        r.files_created.clear();
        assert!(
            residual_creations(&r).is_empty(),
            "a file the repair did not create was already here"
        );

        // X-6: a zero-length creation is out of scope in both
        // directions - never assigned, and never dropped either.
        let mut r = base();
        r.files_patched.push("z.bin".to_string());
        r.files_created.push("z.bin".to_string());
        r.per_file.push(fr("z.bin", 1, 0));
        let kept = residual_creations(&r);
        assert_eq!(kept.len(), 1, "only what has a length to be assigned by");
        assert_eq!(kept[0].name.as_str(), "m.bin");
        assert!(
            d.join("z.bin").exists(),
            "the zero-length creation is left exactly where the repair put it"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// X-8 (31 Aug 2026): a target the repair had to DISAMBIGUATE is
    /// judged at the path it LANDED at, not at one rebuilt from its
    /// reported name.
    ///
    /// Two FileDescs whose names sanitize to one destination would
    /// otherwise share a file, so `par2repair` renames the second to
    /// `<name>.dup-<first 6 bytes of file_id>` while still REPORTING it
    /// by name. Rebuilding the path from that name found nothing there,
    /// so the rebuild the gate exists to refuse produced no `Residual`
    /// at all - and the two names that DID resolve produced two
    /// residuals pointing at ONE file, which `decline` then unlinked
    /// twice.
    ///
    /// Both halves are asserted, because keying on the path is what
    /// makes the second go away rather than merely become rarer: two
    /// targets must be two residuals at two DISTINCT paths.
    #[test]
    fn a_disambiguated_target_is_judged_at_the_path_it_landed_at() {
        use super::residual_creations;
        use nzbkit::par2repair::{FileRepair, RepairReport};
        let d = tmp("dupath");
        // What the engine actually wrote: the first target at the plain
        // path, the second under its file-id tag. Different lengths, so
        // a residual reading the wrong one is visible in the assertion
        // rather than only in the path.
        std::fs::write(d.join("m.bin"), vec![7u8; 1000]).unwrap();
        std::fs::write(d.join("m.bin.dup-0123456789ab"), vec![9u8; 2000]).unwrap();
        let r = RepairReport {
            blocks_rebuilt: 16,
            blocks_adopted: 0,
            adopted_from: Vec::new(),
            // Both reported by NAME, which is all `files_created` has
            // ever carried - and here both names sanitize to `m.bin`.
            files_patched: vec!["m.bin".to_string(), "m.bin.".to_string()],
            files_created: vec!["m.bin".to_string(), "m.bin.".to_string()],
            consumed_sources: Vec::new(),
            per_file: vec![
                FileRepair {
                    name: "m.bin".to_string(),
                    blocks_rebuilt: 8,
                    blocks_adopted: 0,
                    path: d.join("m.bin"),
                },
                FileRepair {
                    name: "m.bin.".to_string(),
                    blocks_rebuilt: 8,
                    blocks_adopted: 0,
                    path: d.join("m.bin.dup-0123456789ab"),
                },
            ],
        };
        let got = residual_creations(&r);
        assert_eq!(
            got.len(),
            2,
            "the disambiguated target produced no candidate, so nothing \
             gates it: {got:?}",
        );
        let mut seen: Vec<(std::path::PathBuf, u64)> =
            got.iter().map(|x| (x.path.clone(), x.len)).collect();
        seen.sort();
        let mut want = vec![
            (d.join("m.bin"), 1000u64),
            (d.join("m.bin.dup-0123456789ab"), 2000u64),
        ];
        want.sort();
        assert_eq!(
            seen, want,
            "a residual must name the file the repair LANDED and carry \
             that file's length"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The half of the W4-06 widening no e2e reaches: with the walk
    /// tree-aware, a file the active sets DO name at a tree path must
    /// still read as claimed. Comparing basenames here - the shape the
    /// root-only test used, where a basename WAS the whole name - would
    /// call every legitimately tree-published file unclaimed and open
    /// the late-set door on every job that has one.
    #[test]
    fn a_tree_published_file_the_active_sets_name_is_not_unclaimed() {
        let d = tmp("claimed");
        std::fs::create_dir_all(d.join("VIDEO_TS")).unwrap();
        std::fs::write(d.join("VIDEO_TS/VTS_01_1.VOB"), b"x").unwrap();
        let named = HashSet::from(["video_ts/vts_01_1.vob".to_string()]);
        assert!(!has_unclaimed(&d, &named));
        // The same file under a name no set speaks for IS the door.
        std::fs::write(d.join("VIDEO_TS/Bq3fJm77ZsK"), b"x").unwrap();
        assert!(has_unclaimed(&d, &named));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Wave-4 row M4-52: the `.par2` skip is a name test, and a
    /// payload wearing that extension must still open the door.
    ///
    /// Both directions matter and only one of them is the row. A real
    /// recovery volume - anything opening with the packet magic - stays
    /// skipped, which is what keeps this door shut on the ordinary job
    /// the module note above says there is nothing behind.
    #[test]
    fn a_par2_named_file_is_skipped_only_when_its_bytes_say_recovery() {
        let d = tmp("par2name");
        let named = HashSet::new();
        // Packet magic under the extension: recovery data, skipped.
        let mut vol = nzbkit::par2::MAGIC.to_vec();
        vol.extend_from_slice(&[0u8; 56]);
        std::fs::write(d.join("spent.par2"), &vol).unwrap();
        assert!(!has_unclaimed(&d, &named));
        // The same name over payload bytes is unclaimed payload.
        std::fs::write(d.join("Bq3fJm77ZsK.par2"), b"not a packet at all").unwrap();
        assert!(has_unclaimed(&d, &named));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The containment on the widened DISCOVERY: a set whose packets
    /// are below the root counts only when an active set published them
    /// there. Without it, a recovery set an in-stream extraction
    /// unpacked into a subdirectory would be repaired against the job
    /// ROOT, where its files are not - noise at best, and at high
    /// enough redundancy its files recreated in a directory that never
    /// wanted them.
    #[test]
    fn a_nested_set_counts_only_when_an_active_set_published_it_there() {
        use super::published_here;
        let d = tmp("vouched");
        let named = HashSet::from(["meta/inner.par2".to_string()]);
        // Root packets are where a set has always been allowed to be.
        assert!(published_here(&d, &HashSet::new(), &[d.join("outer.par2")]));
        // A nested packet the outer set names: the par2-of-par2 chain.
        assert!(published_here(&d, &named, &[d.join("META/inner.par2")]));
        // A nested packet nothing here published: an extracted set.
        assert!(!published_here(
            &d,
            &named,
            &[d.join("Release/its-own.par2")]
        ));
        // One unvouched packet is enough to decline the whole set.
        assert!(!published_here(
            &d,
            &named,
            &[d.join("META/inner.par2"), d.join("Release/its-own.par2")]
        ));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The exclusions the root-only test carried survive the widening,
    /// at every depth: a dot-file and a `.par2` are not what a
    /// non-activated set would be here to name.
    #[test]
    fn dot_files_and_par2_volumes_are_not_unclaimed_at_any_depth() {
        let d = tmp("excluded");
        std::fs::create_dir_all(d.join("META")).unwrap();
        std::fs::write(d.join(".partial"), b"x").unwrap();
        std::fs::write(d.join("META/.partial"), b"x").unwrap();
        std::fs::write(d.join("META/inner.par2"), b"x").unwrap();
        assert!(!has_unclaimed(&d, &HashSet::new()));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Wave-4 row M4-82 (31 Aug 2026): the LEADING-DOT half of the same
    /// name test M4-52 opened one predicate over - and the answer is
    /// different, so this is an interlock and not a fix.
    ///
    /// The row predicted a FAIL: a leftover that sanitizes to a
    /// leading-dot name never arms the late-set pass, so an inner set
    /// that would have given it a real name is never asked. The skip is
    /// real and unconditional (the first half below). What makes it
    /// sound is a property of a different function:
    /// `nzbkit::disk::sanitize_filename_for` never lets a leading dot
    /// through, so no name this job can publish reaches disk wearing one
    /// - not the yEnc header's, the NZB subject's, a PAR2 FileDesc's or
    /// an extracted archive entry's, since every write path joins
    /// through `sanitize_out_name`. There is no route from the wire to a
    /// dotted leftover at all. The dotted files a download directory
    /// really holds are the ones we did NOT write: this daemon's own
    /// `.nzbfast.journal` resume record and its `.nzbfast-*` scratch
    /// (see `nzbkit::disk::hide_from_user`, which says the leading dot
    /// IS the internal-name convention), and the OS's own `.DS_Store`
    /// furniture. Arming the pass on those is what the skip is worth,
    /// and since W4-01 a vouched late set can take a job's SUCCESS away,
    /// so opening this door on a Finder artefact is a real change and
    /// not a free one.
    ///
    /// So the two halves are asserted TOGETHER, and that is the whole
    /// point of the test: neither is a rule this seam owns, and the door
    /// is only safe while BOTH hold.
    ///
    /// THE SANITIZER HALF IS ROW M4-66, and it moved under this test
    /// while this lane was measuring - which is the argument for the
    /// interlock rather than a hypothetical about it. That row is two
    /// real names, `.movie.mkv` and `movie.mkv`, collapsing onto one
    /// on-disk spelling, and its fix took a THIRD option neither the row
    /// nor this test predicted: leading dots are now MAPPED, one `_`
    /// each, rather than deleted or preserved. So the names stay
    /// distinct AND stay undotted, and M4-82 is deader than it was -
    /// deliberately, because that fix's own note gives this exact
    /// argument, listing three passes a preserved dot would have made a
    /// real payload invisible to (`smart::nzbname::is_furniture`,
    /// `repair.rs`'s unclaimed-file scan, `identity.rs`'s release-name
    /// candidates). `has_unclaimed` is a FOURTH and is not on that list.
    ///
    /// If a later lane ever does let a leading dot through, this goes
    /// red on its second half naming M4-82, and the fix is then to skip
    /// the names WE write - `nzbkit::journal`'s leaf and the
    /// `.nzbfast-` prefix - plus OS furniture, rather than every dotted
    /// name. Making that change from this seam BEFORE then is the
    /// four-lanes-deciding-what-counts-as-junk failure the M4-52 note
    /// warns about.
    #[test]
    fn the_dot_skip_is_sound_only_while_nothing_we_publish_can_be_dotted() {
        let d = tmp("dotted");
        // Half one: the skip is a NAME test and nothing weakens it -
        // these bytes are not a packet and no set speaks for them.
        std::fs::write(d.join(".Bq3fJm77ZsK"), b"payload bytes, not a packet").unwrap();
        assert!(
            !has_unclaimed(&d, &HashSet::new()),
            "the leading-dot skip is what M4-82 is about; if this fires the \
             row has been fixed and this interlock should be replaced by the \
             fix's own pin"
        );
        // Half two: and it costs nothing, because no name this job can
        // publish survives sanitize with its leading dot on. A leaf is
        // what `has_unclaimed` tests, so a tree name is checked at its
        // leaf too. What each of these becomes is M4-66's business and
        // is asserted there; all this needs is that none of them keeps
        // the dot.
        for posted in [
            ".Bq3fJm77ZsK",
            ".hidden.mkv",
            "META/.inner.par2",
            "..twice.mkv",
            " .spaced.mkv",
        ] {
            let out = nzbkit::disk::sanitize_out_name(posted);
            let leaf = out.rsplit('/').next().unwrap_or(&out);
            assert!(
                !leaf.starts_with('.'),
                "M4-82 IS NOW LIVE: {posted:?} publishes as {out:?}, whose leaf \
                 keeps its leading dot, so the skip above hides a real leftover \
                 from the late-set pass. See this test's own note for the fix."
            );
        }
        let _ = std::fs::remove_dir_all(&d);
    }
}
