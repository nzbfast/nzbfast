//! The set-repair ladder: everything the job does once verification has
//! said which blocks are bad. The mapped (in-memory, whole-set) pass,
//! the disk-side pass for the sets the mapped route declined, the
//! second-entry duplicate fill off newly materialized volumes, the
//! obfuscated-alias reconciliation the repaired names need, and the
//! `run_set_repair` ladder that sequences the four. Lifted out of
//! settle.rs whole and in file order (TODO 106, 30 Aug 2026), bodies
//! verbatim.
//!
//! One entry point: [`run_set_repair`], which `settle_with_set` calls
//! once it has a damage figure worth spending parity on. The other four
//! are its own rungs and are called from nowhere else, which is what
//! made this the cheapest seam in the file - one call edge out, and the
//! parent's private helpers (`SetPlan`, `RepairOutcome`, `note_dupefill`,
//! `slot_by_hint`) stay visible here because a child module can see
//! them.

use super::*;

/// W4-15: has some earlier pass in this settle already proved every
/// file this set names, so there is nothing left for it to repair?
///
/// Two overlapping recovery sets over one member both take damage (see
/// [`nzbkit::live::LiveVerifier::slot_twin_damage`]), and healing that
/// member once heals it for both - a PAR2 repair re-reads the files it
/// touched and checks them against the FileDesc MD5s, so a proved name
/// is byte-exact. Attempting the second set anyway is wrong twice over:
/// its `needed` was frozen before the repair and reports Unrepairable
/// over bytes that are now correct (which is what failed the job on a
/// post whose sibling set had just healed it), and the mapped route
/// would rewrite a file that is already right from parity it does not
/// have - measured as `repaired file failed MD5 verification` on the
/// very file the other set had just rebuilt.
///
/// Cannot fire on a one-set post (nothing has proved anything before
/// its own attempt) and cannot fire on disjoint sets (their names do
/// not appear in each other's proofs). Empty sets answer false rather
/// than vacuously true.
fn already_proved(set: &nzbkit::par2::Par2Set, proved: &[String]) -> bool {
    !set.files.is_empty()
        && set
            .files
            .iter()
            .all(|f| proved.iter().any(|p| p == &f.name))
}

/// The disk-side PAR2 repair, once per set the mapped route DECLINED.
///
/// Split out of [`run_set_repair`] for the size gate; the body is a
/// verbatim move. Returns whether every declined set was repaired -
/// anything less and the job has damage no parity healed - and extends
/// `proven` with the FileDesc names each successful pass vouched for
/// (a disk repair re-reads its whole set off disk, so it speaks for
/// every file that set names).
#[expect(clippy::too_many_arguments)]
async fn disk_repair_declined_sets(
    declined: &[&SetPlan],
    // Blocks the SECOND-entry duplicate fill proved since `plan.needed`
    // was frozen, per declined plan and in `declined` order. See
    // `fill_from_duplicates_off_materialized_volumes` for why a stale
    // `needed` is not the harmless staleness the reports' is.
    late_healed: &[usize],
    proven: &mut Vec<String>,
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
    nzb: &Nzb,
    out_dir: &Path,
    slots: &[Arc<FileSlot>],
    already: &[usize],
    sniffed_vols: &[usize],
    sniff_bootstrap: Option<usize>,
    mapped_fetched: Vec<usize>,
    mapped_yield: Option<crate::repair::VolumeYield>,
    buf_pool: &Arc<nzbkit::pool::BufPool>,
    extractor: &Arc<nzbkit::extract::Extractor>,
    repair_shortfall: &mut Option<crate::repair::RepairShortfall>,
    cancel: Option<&crate::repair::SideCancel>,
    cpu: &mut crate::lanegate::HeavyCpu,
    donor_dirs: &[PathBuf],
    // X5-10: adoption sources each set's repair proved spent, deferred
    // rather than deleted - see `fetch_and_repair`'s own note.
    spent: &mut Vec<PathBuf>,
    // The volume-named candidates the L1 rescue bought and did not
    // publish, accumulating across sets - see `fetch_and_repair`.
    rescue_left: &mut Vec<PathBuf>,
) -> Result<bool> {
    // The main index BELONGING TO THIS SET (TODO 311). A per-file-set
    // post has one `.par2` index per set, and handing par2cmdline
    // another set's index would have it verify, and try to repair,
    // files this pass is not about. Which set a downloaded index
    // belongs to is read off its own packets rather than guessed
    // from its name - an obfuscated post's index is named a hash.
    // The sniffed bootstrap is the fallback it always was, and is
    // only offered to the set whose id its bytes carry.
    let main_par2_for = |set: &nzbkit::par2::Par2Set| -> Option<PathBuf> {
        // BOUNDED, and the bytes are never wanted for anything else -
        // this closure answers a yes/no and the function returns a
        // `PathBuf`. `is_par2_main` comes off the magic sniff, which
        // matches recovery VOLUMES too, so an unbounded read here held a
        // whole volume to compare 16 bytes. See `set_id_at`.
        let owns = |path: &Path| {
            super::set_id_at(path, super::SET_ID_HEAD).is_some_and(|id| id == set.recovery_set_id)
        };
        for (sidx, slot) in slots.iter().enumerate() {
            if slot.is_par2_main
                && let Some(path) = extractor.slot_path(sidx)
                && owns(&path)
            {
                return Some(path);
            }
        }
        sniff_bootstrap
            .and_then(|s| extractor.slot_path(s))
            .filter(|p| owns(p))
    };
    // Only the sets the mapped route did NOT carry. `mapped_yield`
    // and `mapped_fetched` describe the LAST mapped attempt's own
    // fetch, so they are handed to the first disk pass and not
    // re-offered: a second set's planner must not credit itself with
    // volumes bought for another set's damage.
    let mut mapped_fetched = mapped_fetched;
    let mut mapped_yield = mapped_yield;
    debug_assert_eq!(
        late_healed.len(),
        declined.len(),
        "late_healed is indexed by declined position - a shorter list \
         silently credits the wrong set's healing to nobody"
    );
    // W4-15: the sets that failed, judged AFTER the loop rather than
    // during it. Which set runs first is set order, which follows the
    // in-stream arrival race, so an `&=` here made the verdict depend on
    // it: the weak set over a shared member fails, the strong one two
    // lines later rebuilds the file byte-exact, and the job still exits
    // non-zero over a repair whose work another set had done. Order
    // cannot move a test applied once every set has had its turn.
    let mut failed: Vec<usize> = Vec::new();
    for (i, plan) in declined.iter().enumerate() {
        let set = plan.set.as_ref();
        if already_proved(set, proven) {
            info!(
                target: "repair",
                "set {}: every file it names was already proved by another set's repair - \
                 nothing left to repair",
                plan.index,
            );
            continue;
        }
        // The deficit as it stands NOW, not as it stood before
        // materialize: `fetch_and_repair`'s no-donor-directory early
        // exit is arithmetic and final, so a `needed` that a fill has
        // since healed past reports Unrepairable over good bytes.
        let needed = plan
            .needed
            .saturating_sub(late_healed.get(i).copied().unwrap_or(0));
        if needed < plan.needed {
            info!(
                target: "repair",
                "set {}: the duplicate fill proved {} more block(s) since the plan was made -                  {needed} still needed, not {}",
                plan.index,
                plan.needed - needed,
                plan.needed
            );
        }
        let one = fetch_and_repair(
            servers,
            nzb,
            out_dir,
            set,
            needed,
            main_par2_for(set),
            already,
            sniffed_vols,
            &std::mem::take(&mut mapped_fetched),
            mapped_yield.take(),
            buf_pool.clone(),
            extractor,
            repair_shortfall,
            cancel,
            cpu,
            donor_dirs,
            spent,
            &plan.damaged,
            rescue_left,
        )
        .await?;
        // A successful disk repair re-read the WHOLE set off
        // disk, so it speaks for every file the set names.
        if one {
            proven.extend(set.files.iter().map(|f| f.name.clone()));
        } else {
            failed.push(i);
        }
    }
    for &i in &failed {
        if already_proved(declined[i].set.as_ref(), proven) {
            info!(
                target: "repair",
                "set {}: its own repair came up short, but every file it names was proved \
                 by another set that covers them - nothing of this set's is unrepaired",
                declined[i].index,
            );
        }
    }
    Ok(failed
        .iter()
        .all(|&i| already_proved(declined[i].set.as_ref(), proven)))
}

/// The mapped (in-place, no volume files) repair attempt, once PER SET.
///
/// Split out of [`run_set_repair`] for the size gate; the body is a
/// verbatim move. `declined` collects the sets the route did not carry,
/// which is what [`disk_repair_declined_sets`] reruns - repeating a set
/// the mapped route already healed would re-fetch its volumes for damage
/// that no longer exists. The return is the CONJUNCTION: the materialize path is
/// skippable only if every damaged set came through here, because it is
/// the only other way a set gets repaired at all.
#[expect(clippy::too_many_arguments)]
async fn mapped_repair_every_set<'p>(
    plans: &'p [SetPlan],
    declined: &mut Vec<&'p SetPlan>,
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
    nzb: &Nzb,
    out_dir: &Path,
    already: &[usize],
    sniffed_vols: &[usize],
    buf_pool: &Arc<nzbkit::pool::BufPool>,
    extractor: &Arc<nzbkit::extract::Extractor>,
    reports: &[(usize, nzbkit::live::SlotReport)],
    verifier: &Arc<nzbkit::live::LiveVerifier>,
    recreated_names: &mut Vec<String>,
    mapped_fetched: &mut Vec<usize>,
    mapped_yield: &mut Option<crate::repair::VolumeYield>,
    fast_verify: bool,
    cancel: Option<&crate::repair::SideCancel>,
    cpu: &mut crate::lanegate::HeavyCpu,
) -> Result<bool> {
    if std::env::var_os("NZBFAST_NO_NATIVE_REPAIR").is_some() {
        declined.extend(plans);
        return Ok(false);
    }
    let mut every = true;
    // W4-15: names an earlier plan in THIS pass has already proved. See
    // [`already_proved`] - a second set over the same member has
    // nothing to do once the first has healed it, and attempting it
    // rewrites a correct file from parity that cannot cover it.
    let mut proved: Vec<String> = Vec::new();
    // Read ONCE for the whole pass, not per set: the plan cannot change
    // underneath this - settle runs in the tail after the drain, and the
    // one `activate` call site is on the download worker path.
    let slot_sets = verifier.slot_sets();
    let slot_sets = slot_sets.as_slice();
    for plan in plans {
        if already_proved(&plan.set, &proved) {
            info!(
                target: "repair",
                "set {}: every file it names was already proved by another set's repair - \
                 nothing left to repair",
                plan.index,
            );
            continue;
        }
        let ok = try_mapped_repair(
            servers,
            nzb,
            out_dir,
            &plan.set,
            plan.needed,
            already,
            sniffed_vols,
            buf_pool.clone(),
            extractor,
            reports,
            Some((slot_sets, plan.index)),
            &plan.missing,
            recreated_names,
            mapped_fetched,
            mapped_yield,
            // Fast verify is the default and CRC32 is what the
            // in-stream path trusts too; an operator who turned
            // it off is asking for MD5 everywhere, including
            // here.
            !fast_verify,
            cancel,
            cpu,
        )
        .await?;
        if ok {
            proved.extend(plan.set.files.iter().map(|f| f.name.clone()));
        } else {
            declined.push(plan);
            every = false;
        }
    }
    Ok(every)
}

/// yEnc's framing cost for ONE article, in bytes - the term that makes
/// the alias size band below an additive allowance rather than a pure
/// ratio.
///
/// An NZB's declared byte count is the yEnc-ENCODED size, and yEnc's
/// cost has two parts of quite different shape. The PAYLOAD part is
/// proportional - escapes plus a CRLF every 128 octets, about 3.5% (see
/// [`YENC_EXPANSION_PER_MILLE`]). The FRAMING part is not: every article
/// carries `=ybegin`, `=ypart` and `=yend` lines whose length depends on
/// the posted NAME and the field widths, not on how much payload rides
/// behind them. A ratio-only band therefore reads the framing of a SMALL
/// file as a huge proportional overrun and refuses it.
///
/// Measured 31 Aug 2026 and this is not a corner: the framing on these
/// fixtures is ~118 bytes, so a single-article member under about 700
/// bytes exceeds a 1.2x ceiling - and a PAR2 INDEX file over one member
/// is 648 bytes, posted at 788 (1.216x). Its slot was never excused and
/// a job whose output was complete and MD5-proved failed by name. Full
/// write-up: `research/RECONCILE-BAND-PAIRING-2026-08-31.md`.
///
/// 256 rather than the measured 118: a generous UPPER bound on
/// realistic framing, derived rather than guessed. It said "and rather
/// than the 0.9..1.5 ratio `latesets::fits` uses" until 31 Aug 2026,
/// which stopped being true that same day - that function is a
/// delegation to [`alias_size_band`] now, so this constant is the
/// framing allowance for BOTH seams and there is no competing ratio to
/// be contrasted with. The three lines with maximal field
/// widths and a 74-character release name measure 208 bytes
/// (`=ybegin part=57 total=933 line=128 size=734003200 name=<74 chars>`
/// at 130, `=ypart begin=41943041 end=42729472` at 36, `=yend
/// size=786432 part=57 pcrc32=1a2b3c4d` at 42). Widening the RATIO
/// instead would loosen the gate for every large member at the same
/// time, which is the wrong lever for a cost that is not proportional.
///
/// STATED LIMIT: a file both under about a kilobyte AND posted under a
/// name long enough to push its framing past 256 is still refused. For
/// anything bigger the ratio's own 0.2 slack is orders of magnitude
/// larger than any framing overrun (150 KB against ~100 bytes on a
/// 750 KB article), so this bound only ever binds where it was measured.
const YENC_ARTICLE_FRAMING: u64 = 256;

/// yEnc's PAYLOAD expansion, in parts per thousand: escapes (four
/// critical byte values out of 256, plus a leading `.`) at about 1.6%
/// and a CRLF every 128 output octets at about 1.6%. See
/// [`YENC_ARTICLE_FRAMING`] for the other half of the cost and why the
/// two are modelled separately.
const YENC_EXPANSION_PER_MILLE: u64 = 36;

/// What an NZB would declare for a file of `length` bytes posted in
/// `segments` articles - [`YENC_EXPANSION_PER_MILLE`] on the payload
/// plus [`YENC_ARTICLE_FRAMING`] per article.
///
/// A MODEL and not a measurement: the framing constant is a generous
/// bound, so this over-predicts by roughly 140 bytes per article. That
/// is deliberate and harmless where it is used - [`alias_size_gap_ppm`]
/// ranks candidates by RELATIVE deviation, and the model's error is a
/// small constant fraction where the differences it has to separate are
/// whole block sizes apart.
fn predicted_posted_bytes(length: u64, segments: u64) -> u64 {
    length
        .saturating_add(length.saturating_mul(YENC_EXPANSION_PER_MILLE) / 1_000)
        .saturating_add(YENC_ARTICLE_FRAMING.saturating_mul(segments))
}

/// The alias band: may a slot declaring `posted` yEnc bytes over
/// `segments` articles be the same file as a rebuilt member of
/// `length` bytes?
///
/// NZB byte counts are yEnc-ENCODED and explicitly approximate, so this
/// is a sanity band and not an equality - it is here to stop an
/// unrelated extra file pairing off against a set file of a quite
/// different size. A sizeless NZB pairs nothing.
///
/// AND IT STAYS THAT WAY. The sizeless half is deliberately NOT relaxed
/// alongside shape (b) at the caller: with no posted size there is
/// nothing to sanity-check against, and the spare list is "set members
/// parity rebuilt whole", so dropping the size requirement would let any
/// unrelated short file in this post pair off against a rebuilt
/// descriptor and excuse its own hole. Everything else in this band is
/// what keeps (b) tight - one spare per slot, and the spare must be BOTH
/// unclaimed by any slot (`plan.missing`) and proven by this repair.
///
/// The 0.9 floor is untouched slack for the NZB's own approximation:
/// yEnc only ever EXPANDS, so a truthful `posted` is above `length`
/// already and the floor is there for posters who round. The ceiling is
/// the 1.2 ratio it has always been PLUS [`YENC_ARTICLE_FRAMING`] per
/// article - see that constant for the measured job this cost.
///
/// # Two seams, ONE band (31 Aug 2026)
///
/// `get::latesets::fits` asks the identical question about a LATE set's
/// rebuild rather than about a spare of this repair's own, and until
/// this day it answered it with a second, independent rule - a flat
/// 0.9..1.5 RATIO with no framing term. That is the defect
/// `tools/par2-rule-gate.py` exists to refuse one directory over: one
/// physical fact (yEnc expands a file by a proportional part plus a
/// per-article constant) written down twice, agreeing until somebody
/// moves one. It had already parted. Measured on the three-level chain
/// fixture, the 1.5 ceiling admitted a 42,008-byte rebuild for a slot
/// declaring 53,947 - a ratio of 1.284, which no encoding produces -
/// so two of five sidecar slots were undecidable and a job that
/// delivered every byte byte-exact exited nonzero. Full write-up:
/// `research/LATESET-CHAIN-BAND-2026-08-31.md`.
///
/// So this is the only body, and `fits` delegates to it. Keeping the
/// two spellings apart because the two CONSUMERS differ - a decline
/// deletes a residual there and is only silence here - would be
/// answering one question two ways to serve two answers; the tolerance
/// a decline costs is the caller's business, and the caller is where
/// that argument already lives.
pub(in crate::get) fn alias_size_band(posted: u64, length: u64, segments: u64) -> bool {
    posted > 0
        && length > 0
        && posted.saturating_mul(100) >= length.saturating_mul(90)
        && posted.saturating_mul(100)
            <= length.saturating_mul(120).saturating_add(
                YENC_ARTICLE_FRAMING
                    .saturating_mul(segments)
                    .saturating_mul(100),
            )
}

/// How far a slot's declared `posted` bytes sit from what yEnc would
/// have produced for a rebuilt member of `length` bytes over that
/// slot's own `segments` articles, in parts per million of the
/// prediction. Lower is a better fit; 0 is exact.
///
/// RELATIVE and not absolute, which is the one thing about it worth
/// reading twice. [`predicted_posted_bytes`] is a model, so its error
/// GROWS with the file - an expansion rate wrong by 0.4% is 3 MB on a
/// 750 MB member - and an absolute gap would then rank a true pairing of
/// two large files below a false pairing of two small ones. In parts per
/// million the model's error is a small constant wherever it is measured
/// and the size differences this has to separate (whole PAR2 block
/// counts) are orders of magnitude larger.
fn alias_size_gap_ppm(posted: u64, length: u64, segments: u64) -> u64 {
    let predicted = predicted_posted_bytes(length, segments).max(1);
    posted
        .abs_diff(predicted)
        .saturating_mul(1_000_000)
        .saturating_div(predicted)
}

/// How many distinct SIZE groups of spare a single slot may carry into
/// the best-fit pairing below.
///
/// Purely a memory bound on a crafted post - see the truncation site in
/// [`reconcile_obfuscated_aliases`] for why the direction it errs in
/// only ever refuses an excuse. Reaching it needs more than sixteen
/// distinct rebuilt member sizes inside one slot's band, and a band is
/// about 30% wide: a real PAR2 set's volumes step by whole block counts
/// and a real rar set's volumes are all one size, so nothing measured
/// here comes close.
const ALIAS_CANDIDATES_PER_SLOT: usize = 16;

/// Pair a slot that never claimed a FileDesc against a set member this
/// repair rebuilt whole - issue #9's obfuscated post.
///
/// An obfuscated post names its files nothing like the PAR2 set does -
/// issue #9's shape is par2 created FIRST and every file renamed after -
/// so a file the set covers and parity just rebuilt still lands in
/// `uncovered_pairs`, purely because its posted subject is a hash. Left
/// alone that fails a job whose output is complete and MD5-proved.
///
/// Reconcile those against set files that no slot claimed and THIS
/// repair rebuilt whole and proved: one FileDesc per slot, only for a
/// slot the matcher never gave a verdict on (see the two shapes at the
/// eligibility test below - arrived nothing, or an incomplete head that
/// left the md5-16k tier nothing to hash), and only when the declared
/// sizes agree ([`alias_size_band`]). Whatever stays unpaired still
/// fails the job, so a genuine out-of-set loss is untouched.
///
/// THE PAIRING IS GLOBAL BEST-FIT AND NOT FIRST-FIT, which is the half
/// this function got wrong until 31 Aug 2026. `spare` is the union over
/// EVERY active plan's proven set-missing members, and the old rule
/// walked the uncovered slots in order and handed each the FIRST spare
/// its band admitted. A wide band plus two levels of colliding sizes is
/// then decided by slot order: measured on the two-level chain fixture,
/// the payload slots `pay1` (48,000 bytes) and `pay2` (20,000) were
/// excused against set A's `setb.vol03+4.par2` (43,796) and
/// `setb.vol01+2.par2` (22,520) - two PAR2 VOLUMES of a set neither
/// payload file belongs to - and the two sidecar slots those volumes
/// were really for were left uncovered instead. The COUNT was conserved
/// (a pass excuses at most one slot per spare), which is why nothing had
/// ever reported it; what was wrong was the certificate. The excuse is a
/// claim that a slot's bytes are on disk PROVEN, and here it was made
/// about a file that was not on disk at all at that moment, on the
/// strength of an unrelated volume's length.
///
/// So every admissible (slot, spare) pair is scored by
/// [`alias_size_gap_ppm`], the pairs are taken best-first across ALL
/// slots, and each slot and each spare is consumed at most once. Nothing
/// downstream is weakened by this: the counting invariant the
/// `a_chain_with_a_genuinely_lost_file_still_fails` control rides on is
/// one spare per slot, which is unchanged. What changes is WHICH slot a
/// spare goes to when more than one is in band, and the answer is now
/// the one that fits best rather than the one that comes first.
///
/// Per-slot best-fit was measured and is NOT enough: two slots whose
/// only in-band spare is the same file are still decided by whichever is
/// reached first, which is exactly the `pay1`/`bb3` collision above.
///
/// STATED LIMIT, because it is the one thing a greedy rule cannot
/// promise: what comes out is a MAXIMAL matching and not a MAXIMUM one.
/// So is first-fit - every pair is considered, and one is skipped only
/// once its slot or its size group is spent, so no slot ends with an
/// available in-band spare either way - but two maximal matchings of one
/// graph can differ in size, and a contrived graph exists where taking
/// the better fit first costs an excuse. It needs a slot whose declared
/// bytes are BELOW the member's own length, which is what the 0.9 floor
/// admits for posters who round and which yEnc itself cannot produce: it
/// only ever expands. On both measured fixtures the count went UP, not
/// down - the three-level chain excuses ten slots where first-fit
/// excused nine. A maximum-cardinality matching is Hopcroft-Karp over a
/// graph this is bounded to 16 edges per slot for, and is not worth its
/// interaction with the delete refusal below for a post that cannot
/// exist.
///
/// A free function rather than a block inside [`run_set_repair`],
/// which was at 456 of the size gate's 500-line ceiling on 30 Aug
/// 2026, and this band is one subject with one rule. The
/// `repair-rs-fn-ceilings` split has since given that function room
/// (341 lines on 31 Aug 2026), so the ceiling is no longer the reason
/// to keep this out of line - the one subject is. It is per JOB and
/// not per set -
/// the spare list is the union of every plan's unclaimed-and-proven
/// members, so it must stay OUTSIDE the per-set repair loop.
fn reconcile_obfuscated_aliases(
    plans: &[SetPlan],
    verifier: &Arc<nzbkit::live::LiveVerifier>,
    extractor: &Arc<nzbkit::extract::Extractor>,
    slots: &[Arc<FileSlot>],
    slot_file: &[usize],
    nzb: &Arc<Nzb>,
    set_files_proven: &[String],
    uncovered_pairs: &mut Vec<(usize, &str)>,
) {
    if uncovered_pairs.is_empty() {
        return;
    }
    let spare: Vec<&nzbkit::par2::Par2File> = plans
        .iter()
        .flat_map(|plan| plan.set.files.iter().map(move |f| (plan, f)))
        .filter(|(plan, f)| {
            plan.missing.iter().any(|m| m == &f.name)
                && set_files_proven.iter().any(|p| p == &f.name)
        })
        .map(|(_, f)| f)
        .collect();
    // Two shapes may be an alias, and the second one is here because
    // the first sentence of this comment used to be the whole rule and
    // gave a FALSE reason for refusing the rest.
    //
    // (a) THE SLOT ARRIVED NOTHING. No yEnc name ever reached the
    //     matcher, so it had nothing to claim its FileDesc with. This
    //     is issue #9's own shape and the one the e2e fixture drives.
    //
    // (b) THE MATCHER NEVER REACHED A VERDICT. The old rule refused
    //     every slot that wrote bytes, reasoning that such a slot "had
    //     a yEnc name to claim its FileDesc with, and did not". That is
    //     only true where the matcher got to DECIDE. `head_want()` is
    //     min(16 KiB, declared length), so losing ANY article covering
    //     the first 16k leaves the head incomplete, the md5-16k tier
    //     with nothing to hash and `unmatchable` unset - the slot claims
    //     nothing, produces no report, and had no opinion offered about
    //     it either way. A slot that DID reach a verdict is still
    //     refused, on the original reasoning, which now holds: it either
    //     claimed (and so is not here at all) or was latched unmatchable
    //     by a completed head that matched no FileDesc.
    //
    // `slot_undecided` is the verifier's own answer to (b) - the latch
    // and the claim are its state, not something to re-derive off
    // article counters out here.
    let eligible = |i: usize| {
        let s = &slots[i];
        s.missing.load(Ordering::Relaxed) == s.total_segments || verifier.slot_undecided(i)
    };
    // Spares GROUPED BY LENGTH, each group holding the indices into
    // `spare` of the members of that size, in `spare` order.
    //
    // The grouping is not tidiness, it is what makes the pairing below
    // affordable AND what makes its tie count exact. Two members of the
    // same length score identically against every slot, by construction
    // - the score is a function of (posted, length, segments) and
    // nothing else - so they are one candidate with a supply, never
    // several candidates that happen to agree. That collapses the
    // candidate list from one entry per SPARE to one per distinct SIZE,
    // which is the difference between O(slots x members) and O(slots x
    // sizes) of memory on a post whose set members are all the same size
    // - the shape a rar set of 100 equal volumes has, and the shape a
    // crafted NZB could take to thousands.
    //
    // Built by SORTING and chunking rather than by scanning the groups
    // built so far for each member: the scan is quadratic in the spare
    // count, and PAR2 permits 32,768 files in one recovery set.
    let mut by_length: Vec<usize> = (0..spare.len()).collect();
    by_length.sort_unstable_by_key(|k| (spare[*k].length, *k));
    let mut groups: Vec<(u64, Vec<usize>)> = Vec::new();
    for k in by_length {
        match groups.last_mut() {
            Some((len, members)) if *len == spare[k].length => members.push(k),
            _ => groups.push((spare[k].length, vec![k])),
        }
    }
    // Every admissible (slot, size-group) pairing, scored. `u` indexes
    // `uncovered_pairs`, `g` indexes `groups`; the score leads so the
    // sort is best-first, and the two indices follow it so a tie is
    // broken deterministically rather than by iteration order.
    let mut pairs: Vec<(u64, usize, usize)> = Vec::new();
    let mut mine: Vec<(u64, usize)> = Vec::new();
    for (u, (i, _)) in uncovered_pairs.iter().enumerate() {
        if !eligible(*i) {
            continue;
        }
        let file = &nzb.files[slot_file[*i]];
        let posted = file.bytes();
        let segments = file.segments.len() as u64;
        mine.clear();
        for (g, (length, _)) in groups.iter().enumerate() {
            if alias_size_band(posted, *length, segments) {
                mine.push((alias_size_gap_ppm(posted, *length, segments), g));
            }
        }
        // A BOUND, and the direction it errs in is the safe one. Even
        // grouped, a set whose member sizes all sit inside one band -
        // thousands of files a few percent apart, which nothing forbids
        // - would put every size in every slot's list and take the
        // memory back to the product. Keeping the best few is enough:
        // a slot only ever reaches its Nth choice once N-1 whole size
        // groups have been exhausted by better-fitting slots, and
        // dropping the tail can only ever leave a slot UNEXCUSED, which
        // fails the job by name rather than greening over a loss.
        if mine.len() > ALIAS_CANDIDATES_PER_SLOT {
            mine.sort_unstable();
            mine.truncate(ALIAS_CANDIDATES_PER_SLOT);
        }
        pairs.extend(mine.iter().map(|(score, g)| (*score, u, *g)));
    }
    pairs.sort_unstable();
    let mut paired: Vec<Option<usize>> = vec![None; uncovered_pairs.len()];
    let mut group_next: Vec<usize> = vec![0; groups.len()];
    // A slot the delete below REFUSED, which is not the same as a slot
    // that simply found no spare: its spare goes back to the pool for
    // whoever else is in band for it, and the slot is never offered
    // another one. That is the pre-31-Aug behaviour preserved exactly.
    let mut refused = vec![false; uncovered_pairs.len()];
    for (_, u, g) in pairs.iter().copied() {
        if paired[u].is_some() || refused[u] || group_next[g] >= groups[g].1.len() {
            continue;
        }
        let k = groups[g].1[group_next[g]];
        let (i, _) = uncovered_pairs[u];
        let s = &slots[i];
        let f = spare[k];
        // The slot's own bytes, where it HAS any, are a HOLED file, and
        // that is true by construction rather than by inference: every
        // route to this line put the slot on the uncovered list, and
        // that list is exactly "missing, remaining, errors or abandoned
        // above zero" plus the census's own sparse findings, which are
        // slots whose declared range was never fully written. So there
        // is no reading of this on-disk file under which it is data
        // somebody wants, and the set has just rebuilt the same content
        // whole and MD5-proved beside it.
        //
        // Shape (a) leaves nothing on disk. Shape (b) - and W4-04's
        // damaged identical-head twin, which the whole-file tier
        // declines on purpose - both wrote one under the posted hash,
        // and greening with it still in the output directory hands an
        // *arr a hash-named near-copy of the real payload. That is
        // `drop_spared_metadata`'s argument one file over ("a holed .nfo
        // looks exactly like a real .nfo") and it gets the same answer:
        // delete it, and if the delete fails REFUSE THE EXCUSE rather
        // than green over it - the slot then stays on the uncovered list
        // and fails the job by name.
        //
        // Guarded on the name, because the one thing that must never
        // happen here is deleting the rebuilt member itself: `slot_path`
        // tracks a verified-name publish, so a slot whose file WAS
        // renamed into a set name reports that name and is left alone.
        if let Some(path) = extractor.slot_path(i) {
            let on_disk = path
                .file_name()
                .map(|n| nzbkit::disk::sanitize_out_name(&n.to_string_lossy()).to_lowercase());
            let is_a_proven_set_file = on_disk.as_ref().is_some_and(|n| {
                *n == nzbkit::disk::sanitize_out_name(&f.name).to_lowercase()
                    || set_files_proven
                        .iter()
                        .any(|p| nzbkit::disk::sanitize_out_name(p).to_lowercase() == *n)
            });
            if !is_a_proven_set_file
                && path.exists()
                && let Err(e) = std::fs::remove_file(&path)
            {
                warn!(
                    target: "repair",
                    "{} holds the superseded partial the set rebuilt as {}, and it \
                     could not be removed ({e}) - refusing to report success with a \
                     hash-named copy of the payload still in the output directory",
                    s.hint, f.name
                );
                refused[u] = true;
                continue;
            }
        }
        paired[u] = Some(k);
        group_next[g] += 1;
        // Which member these bytes WERE is only decided where nothing
        // else fits the slot exactly as well. Two identical-head twins
        // BOTH damaged are the same LENGTH, so they score identically
        // and there is nothing here that can tell them apart - the line
        // says so instead of naming one, because "it was rebuilt as X"
        // is an identity claim and an arbitrary one is the defect this
        // whole class is about. A TIE and not the old "how many spares
        // were in band", which counted every merely-plausible member and
        // so said "undecided" about pairings the score decides outright.
        // Nothing downstream needs the pairing: the excuse is per SLOT,
        // the delete above keys on the slot's own path, and each member
        // was proved on its own MD5 by the parity rebuild.
        //
        // Counted over what was UNCLAIMED at this moment, the way the
        // pre-31-Aug rule counted its own band: a twin another slot has
        // already been given is no longer a candidate for this one.
        let tied = groups[g].1.len() - group_next[g] + 1;
        if tied > 1 {
            info!(
                target: "repair",
                "✔ {} never arrived whole under its posted name, and the set \
                 rebuilt {n} member(s) of its size whole and MD5-proved - which \
                 of them these bytes were is not decided here, and nothing \
                 downstream needs it to be",
                s.hint,
                n = tied
            );
        } else {
            info!(
                target: "repair",
                "✔ {} never arrived whole under its posted name, and the set rebuilt \
                 it as {} ({} bytes, MD5-proved)",
                s.hint, f.name, f.length
            );
        }
    }
    // `paired` is indexed the way `uncovered_pairs` is, and `retain`
    // visits each element exactly once in the original order - which is
    // documented behaviour and is what makes the counter beside it
    // sound. A slot the pairing never reached, or reached and REFUSED,
    // stays on the list and fails the job by name.
    let mut u = 0usize;
    uncovered_pairs.retain(|_| {
        let keep = paired[u].is_none();
        u += 1;
        keep
    });
}

/// Put the census's sparse findings on the uncovered list BEFORE the
/// reconciliation reads it, as pairs carrying their slot index.
///
/// W4-04's fix, and it is entirely about ORDER. A slot whose bytes are
/// the DAMAGED copy of a set member claims no FileDesc - the whole-file
/// tier declines on purpose, see `live.rs::try_match_whole` - so the
/// repair recreates the member from parity, adopting that very slot's
/// good blocks, and proves it. [`reconcile_obfuscated_aliases`] excuses
/// the slot for exactly that reason. Appending the census hints AFTER it
/// put the same slot straight back on the list under its posted hash, so
/// a job whose output was complete and MD5-proved still failed - and
/// failed only when the damaged twin settled FIRST, which is a
/// completion order deciding recoverability.
///
/// Resolved through `slot_by_hint`, which refuses a hint naming no slot
/// or two: such a hint keeps the old merge at the call site and fails
/// the job as before, because reconciling a slot that cannot be
/// identified is exactly the arbitrary claim this class must not make.
///
/// A slot the VERIFIER HAS SINCE CLAIMED is skipped outright, and that
/// is the same rule the census itself applies one stage earlier - its
/// first exemption is "the recovery set names the file, or the verifier
/// has matched this slot to one of its entries", because such a file is
/// rebuilt from parity out of bytes no decoder in this run ever wrote
/// and the set's own verification is the stronger statement about it.
/// The census asks that question BEFORE settle, and three of the
/// matcher's tiers - the whole-file tier, the twin tier's per-block
/// evidence, and the finish-time name tier - only reach a verdict
/// inside `finish_slot`. So a damaged identical-head twin is flagged
/// sparse under its posted hash and then claims its FileDesc minutes
/// later, and merging the stale finding here priced a file the set had
/// just repaired in place as one "outside the PAR2 set". Whether the
/// repair actually proved it is not this function's question: an
/// unproved set leaves `all_good` false and the job fails on that.
fn merge_sparse_slots<'a>(
    slots: &'a [Arc<FileSlot>],
    verifier: &Arc<nzbkit::live::LiveVerifier>,
    sparse_slots: &[String],
    uncovered_pairs: &mut Vec<(usize, &'a str)>,
) {
    for hint in sparse_slots {
        if let Some(i) = slot_by_hint(slots, hint)
            && !verifier.slot_in_set(i)
            && !uncovered_pairs.iter().any(|(j, _)| *j == i)
        {
            uncovered_pairs.push((i, slots[i].hint.as_str()));
        }
    }
}

/// PLAN M31 item 4 - the SECOND entry point for the duplicate-posting
/// fill, on the volumes the repair has just materialized.
///
/// # The limit this exists to lift
///
/// `dupefill::wanted_files` refuses a slot where
/// [`nzbkit::extract::Extractor::is_mapped`] or `is_chased` holds - a
/// mapped RAR volume and a chased archive keep their bytes in the
/// extractor rather than in a file, so there is nothing to read back or
/// to patch in place. That is most real releases, and it made the whole
/// pass - its wire half and its disk half alike - INERT on them. Pinned
/// from the other side by
/// `daemon_donor::a_store_rar_release_is_reached_by_the_article_fill_once_its_volume_is_a_file`,
/// whose own note measured the two independent gates.
///
/// # Why HERE and not by teaching the pass to feed the extractor
///
/// Both were on the table (M31 handoff item 4 states them as the
/// choice). The materialize loop above has just demoted every mapped
/// and chased slot of a declined set to `SlotMode::RarFallback` with a
/// writer behind it, so at THIS point `is_mapped` and `is_chased` are
/// both false and `Extractor::slot_path` answers - which means the pass
/// runs here with no change to a single one of its gates, and the file
/// half of it (`write_healed`, the whole-file read-back) works on an
/// ordinary file. Feeding the extractor instead would put borrowed
/// bytes through `patch_volume_span` and take on the demote and
/// chase-conflict post-check protocol `crate::repair` carries a hundred
/// lines of commentary about, to save a materialize on jobs that -
/// having got this far - are already being materialized.
///
/// # What it gives up, stated rather than implied
///
/// The first entry point runs before ANY parity is spent. This one does
/// not: the mapped repair above may already have fetched recovery
/// volumes before declining. What it still precedes is every recovery
/// block the DISK route SPENDS - `disk_repair_declined_sets` is the
/// next statement - which is the property that matters, since a fetched
/// slice that is never consumed costs traffic and a consumed one costs
/// the set's ability to rebuild anything else.
///
/// It is also strictly narrower than the first pass rather than a
/// replacement for it: it runs only for sets the mapped route DECLINED,
/// because a set that route carried has no damage left to borrow for.
///
/// # Why the reports are not rewritten, and the one thing that IS
///
/// The first entry point subtracts what it proved from the settle
/// reports (`FillReport::apply_to`) because everything after it reads
/// them. This one does not need to: the disk repair below runs its own
/// verify off disk, so a block healed here is simply a block that pass
/// finds good. The one later reader of `bad_blocks` is
/// `rarfix::DamageHint::from_reports`, and a hint says which ranges may
/// be SKIPPED - so a stale one costs work and never correctness, which
/// is what its own comment at that site already says.
///
/// `SetPlan::needed` IS NOT COVERED BY THAT ARGUMENT, and reading it as
/// if it were cost a job (29 Aug 2026 sweep, M1). It is the deficit
/// frozen before materialize, and `fetch_and_repair` has an arithmetic
/// early exit that trusts it: `have < needed` with no donor DIRECTORY
/// returns `RepairShortfall::Blocks` WITHOUT asking the native verifier
/// anything. So on the asymmetric donor case - the predecessor's NZB
/// still on the spool (this pass runs) but its output directory gone
/// (the early exit is live) - a fill that healed the set past its
/// parity was reported Unrepairable with the good bytes already on
/// disk. Hence the return: blocks newly proved, per declined plan, in
/// `declined` order, subtracted from `needed` at the call site.
#[must_use]
#[expect(clippy::too_many_arguments)]
async fn fill_from_duplicates_off_materialized_volumes(
    declined: &[&SetPlan],
    verifier: &Arc<nzbkit::live::LiveVerifier>,
    extractor: &Arc<nzbkit::extract::Extractor>,
    slots: &[Arc<FileSlot>],
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
    out_dir: &Path,
    donor_nzbs: &[PathBuf],
    donor_dirs: &[PathBuf],
    cancel: Option<&crate::repair::SideCancel>,
    reports: &[(usize, nzbkit::live::SlotReport)],
) -> Vec<usize> {
    if donor_nzbs.is_empty() || declined.is_empty() {
        return vec![0; declined.len()];
    }
    let plain: Vec<ServerConfig> = servers.iter().map(|(c, _)| c.clone()).collect();
    let mut filled = crate::get::dupefill::FillReport::default();
    // ONE budget for the whole pass, outside the loop - see the twin
    // comment at the first entry point. A SECOND budget and not a
    // continuation of that one, deliberately: the materialize and the
    // repair of every damaged set sit between the two passes, so a
    // deadline carried across would already be spent on arrival and
    // this pass would never run at all.
    let mut budget = crate::get::dupefill::FillPass::new();
    let mut healed = Vec::with_capacity(declined.len());
    for plan in declined {
        let one = crate::get::dupefill::fill_from_duplicate_postings(
            &plain,
            &plan.set,
            plan.index,
            verifier,
            reports,
            extractor,
            slots,
            out_dir,
            donor_nzbs,
            donor_dirs,
            cancel,
            &mut budget,
        )
        .await;
        // The blocks this set no longer needs parity for. Counted off
        // `healed_blocks` rather than off `healed`/`local`/`stitched`,
        // because that list is the one whose entries are PROVED against
        // the target set's own MD5 and CRC32 and then written and
        // synced - the same list the first entry point subtracts from
        // the reports.
        healed.push(
            one.healed_blocks
                .iter()
                .map(|(_, b)| b.len())
                .sum::<usize>(),
        );
        filled.absorb(one);
    }
    note_dupefill(&filled);
    healed
}

/// Judge the JOB once, over the union of what every set's repair proved.
///
/// Out of line since 31 Aug 2026, when [`run_set_repair`] sat at 464 of
/// the size gate's 500-line ceiling, and this is the phase its own doc
/// already names as separate: the repairs above are per SET, and the alias
/// reconciliation and the three failure checks below are per job and run
/// once. It was the tail of that function until 31 Aug 2026 and nothing
/// about the ordering changed - `all_good` arrives as the repairs left it
/// and is the only thing these checks subtract from.
#[expect(clippy::too_many_arguments)]
fn judge_repaired_job<'a>(
    mut all_good: bool,
    reextract_failed: Option<String>,
    repair_shortfall: Option<crate::repair::RepairShortfall>,
    plans: &[SetPlan],
    verifier: &Arc<nzbkit::live::LiveVerifier>,
    extractor: &Arc<nzbkit::extract::Extractor>,
    // `'a` ties the hint strings to the slot table they name, exactly as
    // [`merge_sparse_slots`] does one frame down. `run_set_repair` had the
    // same relation and never had to spell it, because inference could see
    // both ends of it inside one body; across a call boundary the `&mut
    // Vec` that function takes is invariant, so it has to be written out.
    slots: &'a [Arc<FileSlot>],
    slot_file: &[usize],
    nzb: &Arc<Nzb>,
    sparse_slots: &[String],
    in_set_bad: Vec<&str>,
    mut uncovered_pairs: Vec<(usize, &'a str)>,
    set_files_proven: Vec<String>,
) -> RepairOutcome {
    // W4-04: the census's sparse findings join the uncovered list HERE,
    // before the reconciliation reads it - see [`merge_sparse_slots`] for
    // what appending them after it cost.
    merge_sparse_slots(slots, verifier, sparse_slots, &mut uncovered_pairs);
    // §9's obfuscated-alias reconciliation, hoisted whole - see
    // [`reconcile_obfuscated_aliases`] for the rule and for the two slot
    // shapes it admits. Out of line because [`run_set_repair`], which
    // this band ran inside, was at 456 of the size gate's 500-line
    // ceiling on 30 Aug 2026, and the band is a self-contained subject; nothing about the ordering changed - it still runs after
    // every set's repair and before the three ✘ checks below.
    if all_good {
        reconcile_obfuscated_aliases(
            plans,
            verifier,
            extractor,
            slots,
            slot_file,
            nzb,
            &set_files_proven,
            &mut uncovered_pairs,
        );
    }
    // TODO 159 item 1: WHETHER the repair worked is what licenses a
    // per-file quarantine, so latch it before the three checks below
    // start subtracting from it. True here means the pass proved the
    // recovery set - `repair_mapped` re-reads every covered file back
    // through the view it wrote through, the disk repair re-reads the
    // whole set off disk - so anything still wrong is named by one of
    // those checks and nothing else is.
    let repair_ok = all_good;
    let mut uncovered_bad: Vec<String> =
        uncovered_pairs.iter().map(|(_, h)| h.to_string()).collect();
    // The census's own findings belong here too. A slot whose
    // articles ALL arrived and still does not cover its declared
    // range has missing/remaining/errors every one at zero, so
    // the partition above cannot see it - it selects on exactly
    // those three counters. The no-PAR2-set branch below already
    // merges these, and the clean-set branch catches them through
    // `incomplete`; this branch did neither, so a job that took
    // ANY damage and carried a lying `=ybegin size` on a file
    // outside the set finished GREEN with a hole in it, and
    // deleted the journal that named what was missing.
    //
    // Safe against the false REDs that shaped the census: it is
    // already exempt for anything the set covers (so a file
    // rebuilt from parity, whose interval map is legitimately
    // empty, never reaches here), for a reconciled deferral, and
    // for every mapped or chased shape that holds less than it
    // declares - `slot_uncovered` answers None for those.
    // Only the hints [`merge_sparse_slots`] could NOT resolve to a single
    // slot are still owed a merge here; everything else has already been
    // through the reconciliation as a pair.
    for hint in sparse_slots {
        if slot_by_hint(slots, hint).is_none() && !uncovered_bad.contains(hint) {
            uncovered_bad.push(hint.clone());
        }
    }
    // Whatever the repair did, it did it inside the recovery set.
    if all_good && !uncovered_bad.is_empty() {
        all_good = false;
        warn!(
            target: "repair",
            "✘ repair succeeded, but {} file(s) outside the PAR2 set are still \
             incomplete: {}",
            uncovered_bad.len(),
            uncovered_bad.join(", ")
        );
    }
    // Short their articles, named by the set, but on a path that
    // never re-read the whole set off disk: unproven bytes, so
    // they fail the job just the same. Reported separately - they
    // are NOT outside the set, and saying so would send a user
    // hunting for a file that is sitting in the recovery set.
    let unproven_bad: Vec<&str> = if all_good {
        let proven: std::collections::HashSet<String> = set_files_proven
            .iter()
            .map(|n| nzbkit::disk::sanitize_out_name(n).to_lowercase())
            .collect();
        in_set_bad
            .iter()
            .copied()
            .filter(|h| !proven.contains(&nzbkit::disk::sanitize_out_name(h).to_lowercase()))
            .collect()
    } else {
        Vec::new()
    };
    if all_good && !unproven_bad.is_empty() {
        all_good = false;
        warn!(
            target: "repair",
            "✘ repaired in place, but {} file(s) the PAR2 set covers are still \
             short and were never proved against the set: {}",
            unproven_bad.len(),
            unproven_bad.join(", ")
        );
    }
    // The ⚠ census above is the last thing the log says about
    // these files, and on its own it reads like the loss stood.
    // Repair rebuilt them from parity and proved each against its
    // whole-file MD5, so the census stays and this line settles
    // what became of it.
    if all_good && !in_set_bad.is_empty() {
        info!(
            target: "repair",
            "✔ {} file(s) that never arrived were rebuilt in full from PAR2 \
             recovery data: {}",
            in_set_bad.len(),
            in_set_bad.join(", ")
        );
    }
    // TODO 159 item 1: name the slots the two ✘ checks just failed on,
    // by INDEX, so the failed-job quarantine can withhold their payload
    // alone. Licensed only by `repair_ok`: without a proved repair the
    // rest of the output has no certificate either, and the quarantine
    // must stay whole-job.
    //
    // `uncovered_pairs` carries its own indices; the census's
    // `sparse_slots` and the unproven in-set names arrive as hints and
    // have to be looked back up. A hint that resolves to no slot, or to
    // two, abandons the whole claim rather than dropping one file from
    // it - an unnamed damaged slot would otherwise look like a healthy
    // one and its payload would ship.
    let unhealed_slots = repair_ok
        .then(|| {
            let named: std::collections::HashSet<&str> =
                uncovered_pairs.iter().map(|(_, h)| *h).collect();
            let mut idx: Vec<usize> = uncovered_pairs.iter().map(|(i, _)| *i).collect();
            for hint in uncovered_bad
                .iter()
                .map(|h| h.as_str())
                .filter(|h| !named.contains(h))
                .chain(unproven_bad.iter().copied())
            {
                idx.push(slot_by_hint(slots, hint)?);
            }
            idx.sort_unstable();
            idx.dedup();
            Some(idx)
        })
        .flatten()
        // A job that is still good has nothing to quarantine, and an
        // empty list would read as "withhold nothing" on a path that
        // never reached the question.
        .filter(|_| !all_good);
    RepairOutcome {
        all_good,
        reextract_failed,
        repair_shortfall,
        unhealed_slots,
    }
}

/// TODO 311: repair EVERY damaged set, then judge the job once.
///
/// The division is what makes this tractable and is worth stating: the
/// repairs are per set (each has its own parity, block size and set id),
/// and everything after them - the re-extract, the RAR recovery-record
/// fallback, the obfuscated-alias reconciliation and the three ✘ checks -
/// is per JOB and runs once over the union of what the repairs proved.
/// Running the whole of this function per set would re-extract the output
/// directory N times and judge the job on one set's evidence.
#[expect(clippy::too_many_arguments)]
pub(super) async fn run_set_repair(
    plans: &[SetPlan],
    verifier: &Arc<nzbkit::live::LiveVerifier>,
    extractor: &Arc<nzbkit::extract::Extractor>,
    journal: &Arc<nzbkit::journal::Journal>,
    slots: &[Arc<FileSlot>],
    slot_file: &[usize],
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
    nzb: &Arc<Nzb>,
    out_dir: &Path,
    buf_pool: &Arc<nzbkit::pool::BufPool>,
    sniff_bootstrap: Option<usize>,
    fast_verify: bool,
    password: Option<&str>,
    sparse_slots: &[String],
    note_activity: &(dyn Fn(&'static str) + Sync),
    // §129: the owner's recovery-fetch cancel handle, threaded the
    // same way `note_activity` is and for a sibling reason - the
    // repair paths below reach the network, and the tail they run in
    // now outlives the download slot, so a deleted job must be able
    // to stop them. `crate::repair::SideCancel`; None on the CLI.
    cancel: Option<&crate::repair::SideCancel>,
    mut damage_in_mapped: bool,
    already: &[usize],
    sniffed_vols: &[usize],
    reports: &[(usize, nzbkit::live::SlotReport)],
    in_set_bad: Vec<&str>,
    uncovered_pairs: Vec<(usize, &str)>,
    // §293: donor directories for the adoption scan - see
    // `fetch_and_repair`, which is the only reader.
    donor_dirs: &[PathBuf],
    // PLAN M31 item 4: the same duplicate postings `settle_with_set`
    // already ran the fill against BEFORE this function, for the
    // second entry point below - the one that reaches the slots the
    // first pass had to refuse.
    donor_nzbs: &[PathBuf],
    // X5-10: where each set's proven-spent adoption sources are
    // RECORDED. Nothing here deletes them - `settle_with_set` sweeps
    // once the late-set pass has also had its turn, because a donor two
    // sets both need is not spent until the second one is done with it.
    spent: &mut Vec<PathBuf>,
    // 31 Aug 2026: the volume-named candidates the L1 rescue bought and
    // did not publish, across every set. An out-param rather than a
    // `RepairOutcome` field, exactly as `spent` above is: the vector the
    // caller owns is what makes the accumulation across sets free. Its
    // one reader is the failing job's quarantine, which has no other way
    // to know these files exist - they have no slot, which is the very
    // reason the rescue had to be written. See `repair/volpayload.rs`
    // for the stated limits.
    rescue_left: &mut Vec<PathBuf>,
) -> Result<RepairOutcome> {
    let mut all_good;
    let mut reextract_failed: Option<String> = None;
    let mut repair_shortfall: Option<crate::repair::RepairShortfall> = None;
    note_activity("repairing");
    // §129: one repair at a time across concurrent tails. The token
    // above already says "repairing", so a queued wait reads truthfully;
    // held for the whole pass (mapped repair, materialize, disk repair)
    // EXCEPT across the recovery fetches, which hand it back for the
    // duration - it gates cores, and an unanswered side-fetch holding it
    // would park every other job's tail (§137.2; see `HeavyCpu`).
    let mut cpu = crate::lanegate::HeavyCpu::acquire().await;
    // M2c.1: first try repairing straight INTO the extracted
    // output through the block→payload mapping - no volume
    // files ever touch disk. Every declined case (gate miss,
    // I/O error, MD5 verify failure) returns false and the
    // materialize path below runs unchanged.
    // Par2 names the mapped repair recreated WHOLE from parity
    // (empty unless it succeeded) - each proved by its
    // whole-file MD5, so they answer the "still short" verdict
    // below.
    let mut recreated_names: Vec<String> = Vec::new();
    // Recovery volumes the mapped attempt pulls off the wire before it
    // can know whether its route survives. A decline hands them to
    // `fetch_and_repair` rather than dropping them on the floor: they
    // are the same blocks for the same damage, already on disk, and
    // re-planning would only buy them again (23 Aug 2026).
    let mut mapped_fetched: Vec<usize> = Vec::new();
    // §282 item 4: what the mapped attempt's own recovery fetch asked
    // this provider for and what came back. A decline hands it to
    // `fetch_and_repair` so the same refusal is not bought twice.
    let mut mapped_yield: Option<crate::repair::VolumeYield> = None;
    // TODO 311: one attempt PER SET. `mapped_ok` is the conjunction -
    // the mapped route has to have carried every damaged set for the
    // materialize path below to be skippable, because that path is the
    // only other way a set gets repaired at all. A set that declines
    // is remembered so the disk pass reruns only what is still owed:
    // repeating a set the mapped route already healed would re-fetch
    // its volumes for damage that no longer exists.
    let mut declined: Vec<&SetPlan> = Vec::new();
    let mapped_ok = mapped_repair_every_set(
        plans,
        &mut declined,
        servers,
        nzb,
        out_dir,
        already,
        sniffed_vols,
        buf_pool,
        extractor,
        reports,
        verifier,
        &mut recreated_names,
        &mut mapped_fetched,
        &mut mapped_yield,
        fast_verify,
        cancel,
        &mut cpu,
    )
    .await?;
    // Mapped repair writes corrected plaintext through the
    // crypto shim, which refreshes chain checkpoints and
    // final-block padding. Persist those facts before any
    // crash can leave a truthful D placement paired with
    // stale pre-repair K/T records.
    journal.record_crypto_events(&extractor.drain_crypto_events());
    // Did a repair actually PROVE the files the set names? Only
    // then does "the set names this file" prove the file: native
    // repair_dir (and par2cmdline behind it) require every file
    // in the set to match its FileDesc whole-file MD5 or the
    // repair fails. The RAR recovery-record fallback never looks
    // at the par2 set at all, so it can never speak for one.
    //
    // The mapped repair proves exactly what it REBUILT: parity
    // as a source recreates a wholly-missing file and
    // `repair_mapped` whole-file-MD5s it through the same view
    // before returning - the same standard, so those names count
    // (`recreated_names`). A file it merely left alone still
    // does not.
    //
    // Seeded from `recreated_names` on BOTH branches since TODO 311,
    // because `mapped_ok` is now a conjunction over several sets and can
    // be false while one set's mapped repair recreated files and proved
    // them. Discarding those on the strength of ANOTHER set's decline
    // would fail the job on `unproven_bad` for a file parity had rebuilt
    // and whole-file-MD5'd.
    let mut set_files_proven: Vec<String> = std::mem::take(&mut recreated_names);
    if mapped_ok {
        // §94 B / row 27: the repair's self-prove (below) vouches for
        // every block of the set, including the ones it just rebuilt,
        // but the verifier's block states were taken before it and
        // never move again. A gated chase parked at a rebuilt block -
        // a routed child decode, gated through the parent's cells - is
        // waiting for exactly this, and without it would sit until
        // `finish()` released it and then run its whole decode in the
        // tail. Release now, so the decode runs behind the repair.
        extractor.release_verify_gate();
        // A mapped repair proves ITSELF: `repair_mapped`
        // re-reads every file of the set back through the same
        // block→payload view it wrote through - whole-file MD5
        // for the files it rebuilt into, per-block CRC32 for
        // the rest - and a mismatch declines the repair instead
        // of returning true. A covered file whose pwrite failed
        // therefore cannot reach here: the bytes that never
        // landed read back wrong. Covered slots are exactly the
        // set's files (the verifier claims each one for at most
        // one slot, and only a claimed slot gets a report), so
        // that re-read leaves none of them untested.
        //
        // A per-slot error counter used to gate this instead,
        // from when the self-prove covered only the rebuilt
        // files. It outlived that fix, and it was never the
        // right test anyway: `slot.errors` counts DECODE errors
        // alongside write errors, and a yEnc CRC failure is
        // precisely the hole the repair just filled. A post
        // with one corrupt article per volume repaired
        // perfectly and then finished Failed, with byte-correct
        // output sitting in the directory.
        //
        // Slots the set does NOT cover are still tested below -
        // there a decode error IS lost bytes, because no
        // recovery block speaks for them.
        all_good = true;
    } else {
        // PAR2 repair operates on volume FILES - materialize every
        // mapped slot of the set (complete ones too: par2 verifies
        // the whole set from disk) under its PAR2 name. A CHASED
        // slot (a posted .7z streaming out of RAM) has no file
        // either and must come down too, or par2 sees it missing
        // and tries to recreate a whole archive we are holding.
        let any_mapped = reports.iter().any(|(s, _)| extractor.is_mapped(*s));
        let any_chased = reports.iter().any(|(s, _)| extractor.is_chased(*s));
        // A RAR chase (depth-0 compressed set) must be claimed for
        // the post-repair re-extract too: its "materialized for
        // repair" demote reason is excluded from the unrar ladder
        // on the promise that this path re-extracts what it
        // materialized, and no other pass owns the set - without
        // the claim the job shipped repaired-but-packed volumes as
        // its output with exit 0. A materialized .7z stays out:
        // the 7z post-pass runs regardless and re-extracting here
        // would only double the work.
        let any_rar_chased = reports.iter().any(|(s, _)| extractor.is_rar_chased(*s));
        // Blocks the second-entry fill proves after `plan.needed` was
        // frozen. Zero when that door does not open at all, which is the
        // ordinary case and the state `needed` was already right for.
        let mut late_healed = vec![0usize; declined.len()];
        if any_mapped || any_chased {
            note_activity("repairing");
            info!(target: "repair", "materializing volumes for repair…");
            damage_in_mapped |= any_mapped || any_rar_chased;
            for (sidx, r) in reports {
                if extractor.is_mapped(*sidx) || extractor.is_chased(*sidx) {
                    // Same GH #63 guard as the settle loop above: a
                    // materialized volume must not be renamed back to a
                    // hash either.
                    //
                    // ASKED THROUGH THE SAME DOOR since 31 Aug 2026
                    // (claim `materialize-gh63-rename`, read-only sweep
                    // finding 2), and the comment above was the whole
                    // defect: this site tested `filedesc_name_is_better`
                    // ALONE where the settle loop also accepts
                    // `held.is_some()`, so the two were one rule spelled
                    // twice and the second spelling refused the #63
                    // DEFERRAL. A slot with an honest subject and a hash
                    // FileDesc kept the honest name, materialized under
                    // it, and the repair below then went looking for the
                    // FileDesc spelling and reported a member missing
                    // that it was sitting on. `deferred_name` could not
                    // answer here until `current_leaf` learned to read a
                    // writerless slot's PENDING name - see its header.
                    //
                    // The take-back is NOT queued here: `settle_slots`
                    // has already run over these same reports and queued
                    // it, and two entries for one slot rename twice to
                    // land in the same place. This rename is the belt -
                    // it fires only if that pass somehow did not, and
                    // then agrees with it by construction because both
                    // ask this predicate.
                    if let Some(pname) = &r.par2_name
                        && (filedesc_name_is_better(&slots[*sidx], pname)
                            || crate::get::publishplan::deferred_name(
                                &slots[*sidx],
                                Some(pname),
                                extractor,
                                *sidx,
                            )
                            .is_some())
                    {
                        extractor.rename(*sidx, pname);
                    }
                    if let Err(e) = extractor.materialize(*sidx) {
                        warn!(target: "repair", "materialize slot {sidx}: {e}");
                    }
                }
            }
            // A chase that had been DROPPING its consumed prefix just
            // materialized with holes there; the repair below could
            // never cover them from parity, so they come back off the
            // wire first (see get/dropped.rs).
            crate::get::dropped::refetch_dropped_volumes(
                extractor, slot_file, servers, nzb, out_dir, buf_pool, cancel,
            )
            .await?;
            // PLAN M31 item 4: those volumes are FILES now, so the
            // duplicate-posting fill can reach them - see
            // [`fill_from_duplicates_off_materialized_volumes`].
            late_healed = fill_from_duplicates_off_materialized_volumes(
                &declined, verifier, extractor, slots, servers, out_dir, donor_nzbs, donor_dirs,
                cancel, reports,
            )
            .await;
        }
        let repaired = disk_repair_declined_sets(
            &declined,
            &late_healed,
            &mut set_files_proven,
            servers,
            nzb,
            out_dir,
            slots,
            already,
            sniffed_vols,
            sniff_bootstrap,
            mapped_fetched,
            mapped_yield,
            buf_pool,
            extractor,
            &mut repair_shortfall,
            cancel,
            &mut cpu,
            donor_dirs,
            spent,
            rescue_left,
        )
        .await?;
        // Repaired volume files on disk → re-extract them cleanly.
        // rc=0 requires the END state to be usable output, not
        // just a successful repair.
        //
        // Whole-file recreation: any set file no slot claimed
        // (`missing_files`) was just rebuilt on disk by this
        // repair - `repaired` re-read the whole set, so the file
        // is there and proven. A recreated file sits on disk
        // exactly like a materialized one and needs the same
        // re-extract pass; without it the job exits 0 with the
        // recreated volumes still packed (the nested pass skips
        // them as the downloaded outer set). Covers the par-only
        // post (no data slots at all, `reports` empty) and the
        // MIXED set - a clean .nfo that reports beside a wholly
        // ghosted .rar. The old test was `reports.is_empty() &&
        // ...`, which read the .nfo's report as proof nothing
        // was recreated and greened the mixed job still packed
        // (Codex H2, 2 Aug). A recreated bare payload passes
        // through the re-extract untouched (no volumes → success).
        let recreated_set = plans.iter().any(|p| !p.missing.is_empty());
        if repaired && (damage_in_mapped || recreated_set) {
            // The ladder's own reason where it has one - a bomb
            // verdict names the DISK, and this sentence names the
            // repair. See [`reextract_dir_why`].
            all_good = match reextract_dir_why(out_dir, password)? {
                Ok(()) => true,
                Err(why) => {
                    reextract_failed = Some(unpack_failure(
                        why,
                        "PAR2 repair succeeded but re-extraction failed",
                    ));
                    false
                }
            };
        } else {
            all_good = repaired;
            if !all_good {
                // PAR2 could not repair - the volumes' own embedded
                // recovery records are the last remaining redundancy.
                //
                // TODO §11 (b): the verifier's block verdicts ride along.
                // A failed repair never rewrote an intact file (native
                // patches damaged blocks in place, par2cmdline rewrites
                // only damaged files), so a slot whose every block
                // verified is still the file the verifier proved - and
                // the RR pass can leave it unopened. Slots the set never
                // claimed are absent from `reports` and get the full
                // pass.
                // The RAR recovery-record rung is per JOB - it opens the
                // volumes in `out_dir`, which no set owns - so the hint
                // takes ONE block size, the largest set's. A hint is a
                // hint: it says which byte RANGES of a volume the
                // verifier proved clean so the pass can skip them, and a
                // range derived from another set's block size is at worst
                // a range not skipped.
                let hint_bs = plans.first().map_or(0, |p| p.set.block_size);
                let hint = crate::rarfix::DamageHint::from_reports(reports, hint_bs);
                // The rung's own reason where it has one, on the same
                // terms as the re-extract arm above: a bomb verdict
                // names the DISK and must be quoted, and an ordinary
                // failure is left to the arms below to word, which is
                // what this site has always done (TODO §249 item 1).
                all_good = match crate::rarfix::try_rar_rr_repair_hinted_why(
                    out_dir,
                    password,
                    Some(&hint),
                ) {
                    Ok(()) => true,
                    Err(why) => {
                        if let Some(why) = why {
                            reextract_failed = Some(why);
                        }
                        false
                    }
                };
            }
        }
    } // mapped_ok else
    // Judge the job once, over the union of what every set's repair proved -
    // see [`judge_repaired_job`], which went out of line on 31 Aug 2026, when
    // this function sat at 464 of the size gate's 500-line ceiling.
    Ok(judge_repaired_job(
        all_good,
        reextract_failed,
        repair_shortfall,
        plans,
        verifier,
        extractor,
        slots,
        slot_file,
        nzb,
        sparse_slots,
        in_set_bad,
        uncovered_pairs,
        set_files_proven,
    ))
}

#[cfg(test)]
mod band_tests;
