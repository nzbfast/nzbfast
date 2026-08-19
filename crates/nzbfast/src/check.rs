//! The pre-flight check command: probes every server for segment availability and renders the Verdict the get command's --preflight consumes.
//!
//! Split out of main.rs verbatim; behaviour unchanged.

use crate::*;
use nzbkit::preflight::{LegOutcome, LegStats, SweepResult};
use std::path::Path;

// ---------------------------------------------------------------------------
// check - pre-flight availability (M2): STAT sweep + verdict
// ---------------------------------------------------------------------------

/// What pre-flight expects the download to do.
///
/// `dropped` names the files whose loss does NOT decide the verdict:
/// Usenet furniture (`.nfo`, `.sfv`, `.txt`, …) that no server has in
/// full. It rides on every variant because a job can lose furniture in
/// any state of repair, and because the count is a separate claim from
/// the payload one - see [`is_droppable_metadata`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    Complete {
        dropped: Vec<String>,
    },
    Repairable {
        est_missing: usize,
        recovery: usize,
        /// At least one recovery volume declares an ordinal but no slice
        /// count (`.vol-NN.par2`), so `recovery` is a FLOOR, not the
        /// budget. Renders as an approximate answer rather than a
        /// comparison the numbers do not support.
        recovery_unknown: bool,
        dropped: Vec<String>,
    },
    Impossible {
        est_missing: usize,
        recovery: usize,
        /// Present when the verdict rests on a budget MEASURED from the
        /// set's own PAR2 Main packet rather than read off volume
        /// filenames. `est_missing` and `recovery` are then BLOCK
        /// counts, not article counts - see [`measured_verdict`].
        measured: Option<Measured>,
        dropped: Vec<String>,
    },
}

/// What a fetched PAR2 Main packet let pre-flight work out.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Measured {
    /// The recovery set's slice size, from its Main packet. The one
    /// fact that turns a volume's BYTES into a block count.
    pub block_size: u64,
    /// Recovery volumes the sweep found on no server at all. Blocks the
    /// NZB promises that Usenet cannot deliver are not a budget, so
    /// these are struck off the ceiling below.
    pub absent_volumes: usize,
}

/// How much of the sampled deficit an IMPOSSIBLE is allowed to lean on,
/// given the sweep that produced it.
///
/// The margin absorbs two different things and only one of them is
/// noise. `est_missing` is extrapolated from a stratified sample, so it
/// carries ordinary sampling error - on the 15 Aug report it read 2,068
/// against a true 1,965, i.e. 5% HIGH. But it is also biased HIGH BY
/// CONSTRUCTION: [`nzbkit::preflight::stratified_sample`] deliberately
/// over-weights the first three and last two indexes of every file,
/// because takedowns nuke the head of a post and truncated uploads lose
/// its tail. Those are the segments most likely to be gone, and the
/// extrapolation weights them as though they were typical. That bias
/// does not shrink the way variance does - a bigger sample measures the
/// same skewed shape more precisely - which is why the margin keeps a
/// floor however small the sample gets, and why the floor may not be
/// lowered on a noise argument alone.
///
/// At the top it does vanish, though: a 100% sweep is a census, not a
/// sample. Every article was asked about, `stratified_sample(n, n)`
/// returns every index whatever its weighting, and there is no
/// extrapolation left to be wrong about - so the deficit is entitled to
/// the whole figure. The live 16 Aug run was at 100% and claimed a floor
/// of 104 blocks where it could have claimed 208.
///
/// Between the two ends this is a straight line rather than a pair of
/// cases, because the daemon's default sample is expected to move: the
/// sibling work making the sweep cheaper may well take it under 10.
///
/// The 0.5 floor is what keeps the reach honest at the bottom: the
/// sample would have to be wrong by 2x, not 5%, before this could stop a
/// job that would have finished. It costs almost nothing, because the
/// posts this exists to catch miss their budget by an order of magnitude
/// (the 15 Aug one: 900 blocks of provable damage against a 40-block
/// ceiling, and 449 blocks still after the halving).
fn sample_margin(sample_pct: u8) -> f64 {
    let t = ((f64::from(sample_pct.min(100)) - 10.0) / 90.0).clamp(0.0, 1.0);
    0.5 + 0.5 * t
}

/// The sampled payload deficit in RAW bytes, after its margin - the one
/// figure both the pre-gate and the verdict lean on, so they cannot
/// drift apart.
///
/// Raw is the load-bearing word. `missing_payload_bytes` comes from
/// `Nzb::File::bytes()`, which is the yEnc-ENCODED size, while a PAR2
/// block size is raw - so the division that turns this into a damage
/// floor must be given raw bytes or it over-counts by the whole yEnc
/// overhead (3.19% on the 15 Aug post). The flat 0.5 margin used to
/// swallow that; a census margin of 1.0 does not, and the "floor" then
/// runs past the number of blocks the damaged file actually has - on
/// that post, 2,063 blocks of a 2,000-block file. See
/// [`nzbkit::par2::min_raw_bytes`] for what the conversion can and
/// cannot claim.
fn margined_deficit_raw_bytes(missing_payload_bytes: u64, sample_pct: u8) -> u64 {
    nzbkit::par2::min_raw_bytes((missing_payload_bytes as f64 * sample_margin(sample_pct)) as u64)
}

/// Could reading the set's block size POSSIBLY condemn this post? Asked
/// before the fetch, and now the WHOLE gate in front of it.
///
/// It arrived behind a second condition, `est_missing > recovery`, which
/// was at that point still the comparison deciding the verdict outright.
/// That condition was far weaker than it looked - on a `.vol-NN.par2`
/// set `recovery` is ZERO, because not one volume name declares a slice
/// count, so ONE missing payload article out of 4,506 satisfied it and
/// pre-flight spent a BODY fetch to learn a number that could never have
/// changed the answer. It has since gone entirely (16 Aug: an article is
/// not a block, so that comparison decides nothing), and it is not
/// missed. It was wrong in the other direction too: a post whose blocks
/// are much larger than its articles reads as comfortable on the count
/// while the bytes do not. The rule below asks the measured question
/// itself, so it is right in both.
///
/// Divide [`measured_verdict`]'s rule through by the block size and it
/// very nearly cancels: `floor(margined / bs) > sum(floor(V_i / bs))`
/// becomes `margined > sum(V_i)`, a comparison of BYTES that needs no
/// block size and no network. False means no block size could have
/// produced an IMPOSSIBLE, so there is nothing to go and get. Both
/// sides come from the same helpers the verdict uses - `margined` from
/// [`margined_deficit_raw_bytes`], so the yEnc conversion cannot differ
/// between the gate and the verdict it is standing in for - and the
/// volumes stay at their full encoded size, exactly as the ceiling
/// takes them.
///
/// The two rules are not identical and the residue is worth stating.
/// The real one floors each volume SEPARATELY, which can only make the
/// ceiling smaller - by up to one block per volume - so there is a band,
/// at most `live_volume_bytes.len()` blocks wide, where the real rule
/// would condemn and this one declines to look. A sweep of 120,000
/// synthetic cases over six real block sizes (4,096 / 384,000 / 768,000
/// / 1,614,720 / 3,840,000 / 5,376,000) put the disagreement at 2.7% of
/// decisions, all of it that band, and all of it in the conservative
/// direction: the post keeps its PROBABLY REPAIRABLE and the real verify
/// decides, which is the fallback this whole design already rests on.
/// Condemning a job whose deficit clears the ceiling by fewer blocks
/// than the set has volumes was never a call worth making - the posts
/// this exists to catch miss by an order of magnitude. With a single
/// live volume there is no residue at all: `floor` is monotone, so the
/// byte comparison and the block one agree exactly.
///
/// A pre-gate sound for EVERY conceivable block size is not on offer and
/// would be worthless if it were: at `bs = margined` the ceiling floors
/// to zero unless some single volume is larger still, so "some block
/// size could condemn this" is true of nearly every damaged post and
/// skips nothing. Any gate cheap enough to be worth having assumes a
/// block size small beside the volumes, which is what every real
/// recovery set has.
///
/// The second branch is [`placed_damage_floor`]'s, and it is not
/// optional: that floor can condemn a post this byte comparison cannot,
/// so without it the gate would skip fetches that would have found an
/// IMPOSSIBLE - silently, and in exactly the scattered-damage band the
/// placed count exists to serve. It cancels the same way. Placement
/// credits at most one slice per credited segment, credited segments
/// are a whole block apart, and all of them sit inside the file's
/// damaged span, so `placed * bs` is at most that span; condemning
/// needs `placed > sum(V_i) / bs`, and the block size divides out to
/// `span > sum(V_i)`. It inherits the assumption above and nothing
/// else, and it still skips the case the gate was built for: a handful
/// of missing articles spans a few hundred KB against megabytes of
/// volumes.
pub(crate) fn block_size_could_condemn(
    missing_payload_bytes: u64,
    sample_pct: u8,
    live_volume_bytes: &[u64],
    damage: &[FileDamage],
) -> bool {
    let live = live_volume_bytes
        .iter()
        .copied()
        .fold(0u64, u64::saturating_add);
    margined_deficit_raw_bytes(missing_payload_bytes, sample_pct) > live
        || damage
            .iter()
            .map(damaged_span)
            .fold(0u64, u64::saturating_add)
            > live
}

/// Encoded bytes from the start of a file's FIRST missing segment to the
/// end of its LAST - the reach of its damage, which is all the pre-gate
/// needs to know about placement.
fn damaged_span(damage: &FileDamage) -> u64 {
    let (Some(&first), Some(&last)) = (damage.missing.first(), damage.missing.last()) else {
        return 0;
    };
    if last >= damage.seg_bytes.len() {
        return 0;
    }
    damage.seg_bytes[first..=last]
        .iter()
        .fold(0u64, |a, &b| a.saturating_add(b))
}

/// Is this NZB file Usenet furniture whose loss should not decide the
/// verdict?
///
/// Issue #23. The old verdict weighed TOTAL missing articles against
/// TOTAL recovery blocks and never asked which file the articles came
/// from, so one absent article in a single-segment `.nfo` beside 51
/// spare blocks printed `REPAIRABLE` - a repair that could never happen,
/// because a `.nfo` is not in the recovery set. The reporter's downloads
/// then failed on every release, over a file their own cleanup settings
/// would have deleted seconds later.
///
/// This is the same predicate the post-drain census now uses to spare
/// such a slot (`smart::is_junk_ext`, via `get::census`), which is the
/// point: pre-flight should predict what the downloader will actually
/// do. Its exclusions are what make it safe - archives and executables
/// are deliberately NOT furniture, so a missing `.rar` or `.mkv` still
/// decides the verdict.
///
/// Two narrowings on top of the shared list:
///
/// - No extension, no spare. An obfuscated post ships hashes for names,
///   and we cannot tell furniture from payload by guessing.
/// - `.par2` is on the junk list (cleanup deletes it) but is not
///   furniture HERE: the main packet is how repair happens at all. The
///   census reaches the same place by skipping recovery slots outright.
pub(crate) fn is_droppable_metadata(name: &str) -> bool {
    let ext = std::path::Path::new(name)
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    !ext.is_empty() && ext != "par2" && crate::smart::is_junk_ext(&ext)
}

/// The verdict, given a PAYLOAD deficit - furniture already set aside.
///
/// Splitting the deficit is what makes the answer honest in both
/// directions. Furniture the set does not cover can never be repaired,
/// so counting it towards `recovery` promised a repair that will not
/// happen (#23); but its articles do not SPEND recovery blocks either,
/// so counting it could equally flip a payload that repairs fine to
/// IMPOSSIBLE. Neither number is the payload's, and only the payload's
/// decides whether the job completes.
///
/// Pre-flight is STAT-only: it never downloads the PAR2 packets, so it
/// cannot read the set's real file list and cannot KNOW that a given
/// `.nfo` is uncovered - it infers it from the name, exactly as the
/// downloader now does. That inference only affects the fate of the
/// file, never the fate of the job: if the set does not cover it the
/// download completes and drops it, and if the set does cover it repair
/// rebuilds it. The copy says both rather than picking one.
///
/// `recovery_unknown` says the budget above is a FLOOR: some recovery
/// volume names an ordinal without a slice count, the `.vol-NN.par2`
/// shape playWEB/NORViNE/GRACE post. Those volumes carry real blocks we
/// cannot count from the name, and pre-flight never downloads the PAR2
/// packets that would say. Summing them as ZERO is what made this
/// report IMPOSSIBLE - aborting the CLI, failing daemon and library
/// jobs - on sets the downloader repairs, because the real repair path
/// estimates the same volumes from their SIZE instead
/// (`repair::recovery_candidates`). Pre-flight cannot borrow that
/// estimate: it needs the set's block size, which only the PAR2 main
/// packet carries. So it declines to claim impossibility it cannot
/// support - the asymmetry is the point, since IMPOSSIBLE stops a
/// download that would have worked while REPAIRABLE only lets the real
/// verify decide (14 Aug sweep).
///
/// That asymmetry stands. What changed on 15 Aug is that pre-flight
/// stopped GUESSING at the missing fact and went and got it:
/// [`measured_verdict`] fetches one small article, reads the block size
/// out of the set's Main packet, and re-asks the question with real
/// numbers. This function still never reaches IMPOSSIBLE on an unknown
/// budget - it has nothing to reach it with.
///
/// `est_missing` is EXTRAPOLATED (a sampled miss is weighted by the
/// file's segments-per-probe, so one miss at 10% sampling counts as ten)
/// and is what the report prints; `proven_missing` is the number of
/// sampled payload articles that actually came back missing on every
/// server. Only the latter may reach IMPOSSIBLE. That split is the same
/// rule [`measured_verdict`] follows on the bytes side, and it is what
/// keeps an edge-clustered loss - which the stratified sampler goes out
/// of its way to find, spending 3 probes on the head and 2 on the tail -
/// from being multiplied by the full weight and refusing a job with
/// three dead articles as though it had thirty. At a 100% sample the two
/// figures are equal and nothing changes.
///
/// What changed on 16 Aug is that the same honesty finally reached the
/// route that actually fires. `recovery_unknown` was only ever half the
/// problem: it says the block COUNT is a floor, and says nothing about
/// the block SIZE - so a set whose every volume declares a count went on
/// comparing missing ARTICLES against declared BLOCKS, two units that
/// coincide only when the poster happens to have made them coincide. The
/// call site's own comment admitted it ("block ~= article for typical
/// posts") and the 15 Aug post is the counterexample: 1,614,720-byte
/// blocks against ~739,536-byte articles, where 1,965 missing articles
/// damaged 1,669 blocks. The error grows with the block size and it runs
/// the WRONG WAY - a post with 4 MB blocks and 739 KB articles loses 500
/// articles into ~100 damaged blocks, and `500 > 300` refused a job that
/// 300 recovery blocks repair with room to spare.
///
/// So names alone no longer condemn anything, and this function has no
/// IMPOSSIBLE left to reach on a counted budget: a deficit that outruns
/// the count is a REPAIRABLE that says why it cannot be sharper, and the
/// caller escalates to [`measured_verdict`], which compares blocks with
/// blocks.
///
/// `live_volumes` is the one exception, and it is not a unit question at
/// all: it counts the recovery volumes the sweep did NOT prove absent,
/// and none of them means no blocks at every block size there is. A post
/// with no recovery data, or whose recovery data is gone from every
/// server, cannot repair a missing article by any arithmetic. That is
/// the only impossibility a sweep can state without reading a Main
/// packet, and it needs no probe to state it.
///
/// Volumes, not their bytes, and the distinction is load-bearing: an NZB
/// may omit the `bytes=` attribute, and the parser reports the absent
/// figure as zero. Reading that zero as "holds nothing" would condemn
/// every post in such an NZB - a floor spent as a ceiling, which is the
/// exact mistake `recovery_unknown` exists to refuse. A volume that
/// exists counts, whatever its record says about its size.
pub(crate) fn verdict_of(
    est_missing: usize,
    recovery: usize,
    recovery_unknown: bool,
    live_volumes: usize,
    dropped: Vec<String>,
) -> Verdict {
    if est_missing == 0 {
        Verdict::Complete { dropped }
    } else if live_volumes == 0 {
        Verdict::Impossible {
            est_missing,
            recovery: 0,
            measured: None,
            dropped,
        }
    } else {
        Verdict::Repairable {
            est_missing,
            recovery,
            recovery_unknown,
            dropped,
        }
    }
}

/// One payload file's damage, as the sweep actually observed it, and
/// the one fact that lets it be placed: the file's exact length.
///
/// `missing` indexes `seg_bytes`, ascending, and names only segments
/// the sweep PROVED absent - never an extrapolation. That is what makes
/// [`placed_damage_floor`] a floor rather than an estimate: every
/// segment it counts is one every server said it did not have.
#[derive(Debug)]
pub(crate) struct FileDamage {
    /// Encoded size of EVERY segment of the file, in posting order.
    pub seg_bytes: Vec<u64>,
    /// Indexes into `seg_bytes` of the segments no server has.
    /// Ascending, no repeats.
    pub missing: Vec<usize>,
    /// The file's EXACT length, from the recovery set's own FileDesc
    /// packet. `None` when the probe did not read one - which says
    /// nothing about whether the set covers the file, so the caller
    /// keeps the byte-count floor for it.
    pub length: Option<u64>,
}

/// The MOST yEnc can inflate a payload, per mille of it.
///
/// Every escaped byte becomes two, and the worst case is every byte
/// escaped; a CRLF every 128 output columns adds 1.5625% on top. 2.032
/// is that product. Nothing about the payload's content can beat it, so
/// a bound that divides by it is one no file can break.
const YENC_MAX_EXPANSION_PER_MILLE: u64 = 2_032;

/// Bytes of an article that are frame rather than encoded payload: the
/// `=ybegin` / `=ypart` / `=yend` lines, plus room for whatever the
/// posting tool counted into the NZB's `bytes=` beside the body. One
/// kilobyte is many times the real figure (~200 bytes), which is the
/// right direction - it is subtracted from a span before that span is
/// believed.
const YENC_ARTICLE_FRAME: u64 = 1_024;

/// A LOWER bound on the RAW bytes behind `encoded` encoded bytes
/// spanning `segments` whole articles of a file whose total yEnc
/// overhead is `file_overhead` (its encoded total minus its exact
/// length).
///
/// Two arguments, and the stronger one wins:
///
/// - **The file's own books.** Overhead is non-negative per article, so
///   no span of a file can have lost more of it than the file lost in
///   total: `raw >= encoded - file_overhead`. Tight for a small file,
///   worthless for a big one - a 3.2 GB post's 103 MB of overhead is 64
///   blocks, so this alone could never place anything.
/// - **yEnc's own ceiling.** An article cannot encode to more than
///   2.032 times its payload plus its frame
///   ([`YENC_MAX_EXPANSION_PER_MILLE`]), so
///   `raw >= (encoded - frame) / 2.032` wherever the span sits. Weak by
///   a factor of two, but it does not care how large the file is, which
///   is exactly the case the first argument cannot serve.
///
/// Neither assumes anything about the CONTENT - not an average encoding
/// ratio, not that the ratio is steady across the file, not that the
/// articles are the same size. Both assume the NZB's `bytes=` is the
/// article's real encoded size give or take the frame, which is the
/// same thing the byte-count floor beside this one already rests on.
fn provable_raw_span(encoded: u64, segments: u64, file_overhead: u64) -> u64 {
    let by_books = encoded.saturating_sub(file_overhead);
    let framed = encoded.saturating_sub(YENC_ARTICLE_FRAME.saturating_mul(segments));
    let by_yenc = (framed as u128 * 1_000 / YENC_MAX_EXPANSION_PER_MILLE as u128) as u64;
    by_books.max(by_yenc)
}

/// Blocks the segments this file has PROVABLY lost must have damaged -
/// counted by where they sit, not by how much they weigh.
///
/// The byte-count floor beside this one
/// ([`nzbkit::par2::min_damaged_blocks`]) asks only how many bytes are
/// gone, so it answers as if every missing byte were poured into as few
/// slices as physically possible. Real damage is not poured, it is
/// SCATTERED: on the 15 Aug post an article is 0.44 of a block, so 456
/// missing articles landing at 456 different offsets damage 596 blocks
/// while their weight can only prove 208. Placement is the whole gap.
///
/// The count is built so that residual error in WHERE a segment sits
/// cannot inflate it. Two facts do that:
///
/// - Only one byte per credited segment is ever used - its first. A
///   segment's own extent is thrown away, so a segment that straddles a
///   boundary is credited with one block and not the two it really
///   damages. That is roughly a quarter of the truth given up on
///   purpose, and it is why nothing here needs to know where a segment
///   ENDS.
/// - A segment is credited only when [`provable_raw_span`] can show its
///   first byte is a whole `block_size` past the last credited one.
///   Every credited byte is then pairwise at least a block from every
///   other, so each sits in a slice of its own, and each is genuinely
///   absent. The count is therefore a subset of the truly damaged
///   slices however far the offset arithmetic drifts.
///
/// The exactness of `length` is what makes the first argument in
/// `provable_raw_span` usable at all, and it is why a file the probe
/// did not describe is skipped rather than guessed at: the NZB's
/// `bytes=` is the ENCODED figure, so a grid laid from it would drift
/// by the whole yEnc overhead - 103 MB, 64 blocks, on that same post.
///
/// Measured against the real thing (4,506 articles, 1,614,720-byte
/// slices, damage scattered as the report found it, weighed at a full
/// census): 456 missing articles place into 328 slices against a true
/// 596, where weight proves 208; 1,965 place into 717 against a true
/// 1,703, where weight proves 899.
///
/// That second row is the shape of the whole thing, and the reason
/// [`measured_verdict`] takes the LARGER of the two rather than
/// replacing one with the other. Weight is blind to placement and gains
/// as damage thickens; placement is blind to weight, gains as damage
/// spreads, and loses whenever missing articles crowd into slices they
/// have to share. On this post they cross at about 30% of the articles
/// gone. Below it placement proves up to twice what weight can, above
/// it weight proves more, and neither is ever above the truth.
///
/// What the gain SCALES with is the sample, and that is the one thing
/// to know before reaching for these figures. Only segments the sweep
/// actually asked about can be placed - there is no extrapolating a
/// count of distinct slices, because a 1-in-10 sample of a contiguous
/// run looks exactly like scattered damage and scaling it up would
/// invent slices that do not exist. So this pays on `check`'s default
/// whole sweep and adds nothing on the daemon's `--sample 10` route,
/// where the extrapolated byte floor is the larger of the two and stays
/// the deficit. A live run of the 15 Aug post at `--sample 10` on 16
/// Aug bears that out: 88 of 451 sampled articles gone, 88 placeable,
/// and the verdict came out of the byte floor's 201 against a 40-block
/// ceiling.
pub(crate) fn placed_damage_floor(damage: &FileDamage, block_size: u64) -> usize {
    let Some(length) = damage.length else {
        return 0;
    };
    if block_size == 0 || damage.missing.is_empty() || length == 0 {
        return 0;
    }
    let encoded_total = damage
        .seg_bytes
        .iter()
        .fold(0u64, |a, &b| a.saturating_add(b));
    // yEnc never shrinks a byte, so a set member LONGER than the sum of
    // its own encoded articles is not this NZB file: either the names
    // collided or the NZB is missing segments outright. Both make the
    // overhead below meaningless, and a grid is worse than no grid.
    if length > encoded_total {
        return 0;
    }
    let overhead = encoded_total - length;
    let mut prefix = Vec::with_capacity(damage.seg_bytes.len() + 1);
    prefix.push(0u64);
    for &b in &damage.seg_bytes {
        let run = prefix.last().unwrap().saturating_add(b);
        prefix.push(run);
    }
    let mut credited = 0usize;
    let mut anchor: Option<usize> = None;
    for &k in &damage.missing {
        if k + 1 >= prefix.len() {
            continue;
        }
        let far_enough = match anchor {
            // The first credit asks only that the article carry a byte
            // at all: one absent byte damages one slice.
            None => provable_raw_span(prefix[k + 1] - prefix[k], 1, overhead) >= 1,
            Some(a) => {
                provable_raw_span(prefix[k] - prefix[a], (k - a) as u64, overhead) >= block_size
            }
        };
        if far_enough {
            credited += 1;
            anchor = Some(k);
        }
    }
    credited
}

/// Second opinion on a "probably repairable", once the set's own block
/// size is in hand.
///
/// The 15 Aug report is the whole reason this exists: 2,068 payload
/// articles missing on every server, seven recovery volumes named
/// `.vol-NN.par2` so not one of them declared a slice count, budget
/// summed to 0, `recovery_unknown` set - and [`verdict_of`] correctly
/// declined to call a job impossible on a budget it could not size. The
/// download then spent 1.9 GB and 153 s reaching the verdict the sweep
/// already had the evidence for. The missing fact was one number, in one
/// packet, in a 42 KB article.
///
/// With it, both halves become bounds rather than guesses, and they lean
/// in opposite directions on purpose:
///
/// - The deficit is the better of two bounds. `missing_payload_bytes`
///   cannot all hide inside fewer than `bytes / block_size` slices
///   wherever they sit; the figure is discounted first
///   ([`sample_margin`]) by however much of it came off a sample rather
///   than a census, and then converted from the NZB's yEnc-ENCODED
///   bytes into raw ones ([`margined_deficit_raw_bytes`]), because the
///   block size it is about to be divided by is raw. Both discounts are
///   load-bearing: without the second, a census-margin deficit claimed
///   2,063 damaged blocks of a file with 2,000 blocks in it, which is
///   not a floor at all. Beside it, [`placed_damage_floor`] asks where
///   the missing segments actually SIT and counts slices that cannot be
///   the same one - and being placement rather than weight, it does its
///   own encoded-to-raw arithmetic from the file's exact length
///   ([`provable_raw_span`]) rather than through that constant. The two
///   are complementary rather than redundant: weight is blind to
///   placement and wins on dense damage, placement is blind to weight
///   and wins on scattered damage, and the crossover on the 15 Aug post
///   sits near 30% of the articles gone. Whichever proves more is the
///   deficit.
/// - The budget is a CEILING. Each live volume is sized by
///   [`nzbkit::par2::max_recovery_blocks`], which divides its ENCODED
///   bytes by the bare block size - so every byte a volume actually
///   spends on packet headers and its repeated critical packets is a
///   block credited to it that it does not hold.
///
/// `live_volume_bytes` is the encoded size of every recovery volume the
/// sweep did NOT prove absent, which is the other half of the answer: a
/// budget that exists in the NZB but not on Usenet is not a budget, and
/// a volume no server carries can hold no blocks for us. Partial
/// availability counts as fully present - the conservative reading, and
/// the one that keeps this from stopping a job the give-up ladder might
/// still have fed.
///
/// One inference survives from the STAT-only days and is deliberately
/// left alone: which files the set actually covers. A payload file the
/// recovery set does not cover contributes bytes to the deficit that no
/// block could ever have repaired - but such a file cannot be repaired
/// at any budget either, so the direction is right, and after the
/// furniture rule the residue is sample images and the like, whose bytes
/// round to nothing beside the archive volumes that decide these posts.
///
/// `None` means the numbers do not support impossibility and the caller
/// keeps its "probably repairable" - the honest fallback, unchanged, for
/// every set that stays unsizable.
pub(crate) fn measured_verdict(
    missing_payload_bytes: u64,
    sample_pct: u8,
    block_size: u64,
    live_volumes: &[(u64, Option<usize>)],
    absent_volumes: usize,
    damage: &[FileDamage],
    dropped: Vec<String>,
) -> Option<Verdict> {
    if block_size == 0 || missing_payload_bytes == 0 {
        return None;
    }
    // A volume whose NZB record carries no `bytes=` reads as zero, and
    // zero here is "unsized", not "empty". Sizing it as empty would put
    // a floor in the ceiling's place - the same error in a different
    // costume - so one unsizable volume declines the whole verdict, as
    // an unreadable block size does.
    if live_volumes.iter().any(|&(bytes, _)| bytes == 0) {
        return None;
    }
    let margined = margined_deficit_raw_bytes(missing_payload_bytes, sample_pct);
    let by_bytes = nzbkit::par2::min_damaged_blocks(margined, block_size);
    // Blocks do not span files, so per-file counts of distinct damaged
    // slices simply add - no file can be crediting another's block.
    //
    // Folded in u64 rather than usize: `usize` is 32 bits on the shipped
    // armv7 build, and every other term here is u64 for the reason
    // `max_recovery_blocks` gives - a count that wraps to 0 is a false
    // verdict on the side of the comparison that stops a download.
    let by_placement = damage
        .iter()
        .map(|d| placed_damage_floor(d, block_size) as u64)
        .fold(0u64, u64::saturating_add);
    let deficit = by_bytes.max(by_placement);
    let ceiling = live_volumes
        .iter()
        .map(|&(bytes, declared)| {
            let by_bytes = nzbkit::par2::max_recovery_blocks(bytes, block_size);
            // A name cannot conjure blocks that will not fit in the
            // volume's bytes, and bytes cannot conjure blocks the name
            // denies, so the smaller of the two is a ceiling wherever
            // both exist. Worth taking because the byte side is loose by
            // construction - encoded bytes are yEnc-inflated by about a
            // third before packet overhead, so a 51-block volume ceilings
            // near 70 on bytes alone. It trusts the name no further than
            // the route this replaced, which condemned posts on the
            // declared sum by itself.
            match declared {
                Some(n) => by_bytes.min(n as u64),
                None => by_bytes,
            }
        })
        .fold(0u64, u64::saturating_add);
    if deficit <= ceiling {
        return None;
    }
    // NOT guarded on "every live volume floors to zero blocks". That
    // was tried for the mixed-set case (a set-blind block size sizing
    // another set's volumes) and it is too broad by far: a present
    // volume that genuinely holds no usable parity for this set - an
    // index file carrying the `.vol-NN` name, or a volume far smaller
    // than the block size - floors to zero honestly, and refusing to
    // conclude anything there rescues posts that really are dead. That
    // is the one verdict pre-flight exists to reach. The reachable half
    // of the mixed-set worry is the UNSIZABLE volume, and the guard
    // above already closes it.
    Some(Verdict::Impossible {
        est_missing: usize::try_from(deficit).unwrap_or(usize::MAX),
        recovery: usize::try_from(ceiling).unwrap_or(usize::MAX),
        measured: Some(Measured {
            block_size,
            absent_volumes,
        }),
        dropped,
    })
}

/// The reason an IMPOSSIBLE gives, in the units the verdict was actually
/// reached in.
///
/// Three callers refuse a job on this verdict - the CLI's `--preflight`,
/// the daemon's opt-in sweep, and the library metadata-only path - and
/// the units differ by ROUTE, not by caller: a budget measured from the
/// set's own main packet counts blocks on both sides, and the
/// no-recovery-at-all route counts articles against a budget of nothing,
/// where the units cannot disagree because one side is zero. Written
/// once so a number that is right cannot become a sentence that is
/// wrong in two places out of three.
///
/// What is NOT here any more is the sentence that read a count of
/// missing ARTICLES against a count of declared BLOCKS as though the two
/// were comparable. That comparison is gone from the code, so the copy
/// that reported it went with it: no route can now produce those two
/// numbers side by side.
pub(crate) fn impossible_reason(
    est_missing: usize,
    recovery: usize,
    measured: &Option<Measured>,
) -> String {
    match measured {
        None => format!(
            "an estimated {est_missing} payload segment(s) are unavailable on every \
             server, and the post carries no recovery data the sweep could find - so \
             there is nothing to rebuild them from"
        ),
        Some(m) => format!(
            "the payload no server has damages at least {est_missing} block(s) of {}, \
             against at most {recovery} recovery block(s) the NZB can still deliver",
            block_size_label(m.block_size)
        ),
    }
}

/// The order [`block_size_probe`] offers servers to `fetch_block_size`:
/// flatrate first, metered behind them.
///
/// The probe is nzbfast's OWN curiosity, which is exactly what
/// `ServerConfig::may_spend_on_measurement` governs - and every other
/// curiosity caller in the tree honours it, while this one dialled the
/// list in config order. `fetch_block_size` walks that order and stops
/// at the first server that answers, so a block account listed ahead of
/// a flatrate one was billed for bytes the flatrate server would have
/// supplied identically.
///
/// A partition and NOT a filter, deliberately. On a block-only install
/// every server fails the predicate; a hard filter would then skip the
/// probe altogether, leave the budget unsizable, and let the job
/// download the whole dead post - 1.9 GB on the 15 Aug report against
/// the ~1.5 MB worst case here. Spending less is the point, so do not
/// "tidy" this into a `retain`.
fn probe_order(servers: &[nzbkit::config::ServerConfig]) -> Vec<nzbkit::config::ServerConfig> {
    let (free, metered): (Vec<_>, Vec<_>) = servers
        .iter()
        .cloned()
        .partition(|s| s.may_spend_on_measurement());
    free.into_iter().chain(metered).collect()
}

/// A block size in the unit it is actually in.
///
/// Live sets run from a few hundred KB to several MB a block, and
/// `{:.1} MB` renders the small end as "0.0 MB" - a figure that reads as
/// a bug in the sentence it is supposed to be explaining.
pub(crate) fn block_size_label(block_size: u64) -> String {
    if block_size >= 1_000_000 {
        format!("{:.1} MB", block_size as f64 / 1e6)
    } else {
        format!("{:.1} KB", block_size as f64 / 1e3)
    }
}

/// Go and get the set's block size: pick the cheapest `.par2` file the
/// sweep has not already condemned, and pull a couple of its articles.
///
/// The cost, which is the whole argument for doing this at all. On the
/// 15 Aug post the pick was a 41,901-byte article - one BODY, one round
/// trip, well under a second - beside a STAT sweep that already costs
/// 119-145 s and a wrong REPAIRABLE that cost 1.9 GB and 153 s. Worst
/// case is two articles of a large recovery volume, ~1.5 MB, still under
/// a thousandth of what one wrong verdict spends.
///
/// Which file is [`Nzb::par2_seed_file`]'s question, not a second answer
/// to it: the download path already had to solve "no main `.par2` in the
/// NZB, so bootstrap the set from the smallest volume" and this is the
/// same pick. The runner-up is tried too, because the smallest par2 file
/// being gone from every server is exactly the kind of post that reaches
/// here.
///
/// First segment, then last. A par2 INDEX carries its Main packet in the
/// first bytes (11 of 12 files in the sample corpus put it at offset 0,
/// the twelfth at 74,808 of 76,856 - still one article). A recovery
/// VOLUME interleaves its critical packets between slices, so its Main
/// copy can sit megabytes in; the tail is the better second guess,
/// because the packet run at the end of a volume is where the Main and
/// Creator packets landed in the one real volume measured (19,026,188
/// and 19,028,120 of 19,028,236 bytes).
///
/// Returns the files it actually asked about alongside the answer. Run
/// BEFORE the sweep there is no `absent_files` list to skip, so a
/// caller that comes up empty needs to know whether it drew the two
/// par2 files Usenet no longer has - the one failure a second, now
/// informed, attempt can fix.
async fn block_size_probe(
    servers: &[nzbkit::config::ServerConfig],
    nzb: &Nzb,
    absent_files: &[usize],
) -> (Option<nzbkit::preflight::ProbedSet>, Vec<usize>) {
    let mut candidates: Vec<usize> = nzb
        .files
        .iter()
        .enumerate()
        .filter(|(fi, f)| {
            matches!(f.kind(), FileKind::Par2Main | FileKind::Par2Volume)
                && !f.segments.is_empty()
                && !absent_files.contains(fi)
        })
        .map(|(fi, _)| fi)
        .collect();
    // The seed file first - a `.par2` index over a volume, then smallest
    // - and everything else behind it in the same order, so the runner-up
    // is the next cheapest rather than whatever the NZB happened to list.
    candidates.sort_by_key(|&fi| {
        (
            nzb.files[fi].kind() != FileKind::Par2Main,
            nzb.files[fi].bytes(),
        )
    });
    // Servers that may fund measurement first, metered ones only if
    // none of them answered (`probe_order`): a prepaid block account
    // must not be billed to sharpen an OPTIONAL estimate.
    let probe_order = probe_order(servers);
    let tried: Vec<usize> = candidates.iter().copied().take(2).collect();
    for &fi in &tried {
        let segs = &nzb.files[fi].segments;
        let mut ids = vec![format!("<{}>", segs[0].message_id)];
        if segs.len() > 1 {
            ids.push(format!("<{}>", segs[segs.len() - 1].message_id));
        }
        let name = nzb.files[fi]
            .filename_hint()
            .unwrap_or(&nzb.files[fi].subject);
        println!("  reading the recovery set's block size from {name}");
        if let Some(probed) = nzbkit::preflight::probe_recovery_set(&probe_order, &ids).await {
            return (Some(probed), tried);
        }
    }
    (None, tried)
}

/// Does this NZB carry more than one PAR2 recovery SET?
///
/// The question the declared-count cap has to ask before it may trust a
/// volume's name. `block_size_probe` picks the cheapest Main or volume
/// anywhere in the NZB and hands back a block size with no recovery-set
/// identity on it (`ProbedSet` has no set field), and `live_volumes`
/// then takes EVERY `Par2Volume` the NZB carries. On a single-set NZB
/// that is exactly right. On a two-set one it can size set B's volumes
/// with set A's block size.
///
/// That used to be harmless, and the reason it stopped is worth stating
/// because a previous review refuted this very case on it. The old
/// ceiling was the bare `max_recovery_blocks(bytes, block_size)`, and
/// `measured_verdict`'s rule divides through: `floor(margined / bs) >
/// sum(floor(V_i / bs))` cancels to a comparison of bytes, so a wrong
/// block size dropped out on both sides and could not by itself flip a
/// verdict. The `min(by_bytes, declared)` cap broke that cancellation -
/// `declared` comes off a filename and does not scale with `bs` at all.
/// So with a block size smaller than the volumes' true one the deficit
/// inflates while the ceiling saturates at the declared sum, and a
/// repairable set can be condemned before it is ever fetched. (The cap
/// and that refutation landed on branches that were not ancestors of
/// each other and met in a merge, which is how the two crossed without
/// anyone reconciling them.)
///
/// Reported by name rather than by set identity because carrying set
/// identity from the probe through the volumes and the payload, and
/// adjudicating each set on its own, is a far larger change than the
/// bug warrants. Dropping the cap on multi-set NZBs restores the
/// scale-invariant behaviour exactly where it was safe, and keeps the
/// cap's whole benefit on the single-set NZBs that are very nearly all
/// real posts.
///
/// Unparseable par2 names are IGNORED rather than counted as sets of
/// their own. A name too obfuscated to yield a stem is also too
/// obfuscated to yield a declared count, so it can never be capped and
/// must not be allowed to inflate this. Mis-splitting a single-set NZB
/// would only drop the cap there - it refuses strictly less, never
/// more - but it would quietly cost the benefit, so it is worth not
/// doing by accident.
fn multiple_par2_sets(nzb: &Nzb) -> bool {
    let mut stems: Vec<String> = Vec::new();
    // A PAR2 file whose name reduces to nothing at all.
    let mut anonymous = false;
    for f in &nzb.files {
        if !matches!(f.kind(), FileKind::Par2Main | FileKind::Par2Volume) {
            continue;
        }
        let quoted = f.filename_hint().is_some();
        let name = f.filename_hint().unwrap_or(&f.subject).to_ascii_lowercase();
        // `.volNNN+MM.par2` -> the stem in front of `.vol`; a bare
        // `.par2` Main -> the stem in front of that. Same two shapes
        // `par2_vol_count` reads, so the two cannot disagree about what
        // a volume of a set is called.
        let stem = match nzbkit::nzb::par2_vol_suffix(&name) {
            Some(vol) => &name[..vol],
            // kind()'s OWN rule for a Main, not `strip_suffix(".par2")`:
            // `.par2` ending the name or followed by whitespace. The two
            // have to agree, and with strip_suffix they did not - a Main
            // classified from an unquoted raw subject ("setb.par2 yEnc
            // (1/1)") is a Par2Main to kind() and was skipped here, so a
            // second set represented ONLY by such a Main left cross_set
            // false and the declared-count cap alive. That cap can
            // refuse a genuinely repairable post (18 Aug sweep).
            None => match name.match_indices(".par2").find(|(i, _)| {
                let rest = &name[i + ".par2".len()..];
                rest.is_empty() || rest.starts_with(char::is_whitespace)
            }) {
                Some((i, _)) => &name[..i],
                None => continue,
            },
        };
        // A RAW subject carries more than the filename, and the extra is
        // per-file: "[01/02] - set.par2" and "[02/02] - set.vol000+51.par2"
        // are one set whose stems differ only by a counter, and comparing
        // the whole prefix split them and dropped a trustworthy declared
        // cap. Whitespace is what ends a filename inside a subject - the
        // rule par2_vol_suffix's own doc cites - so take the last
        // whitespace-delimited token. Only for raw subjects: a QUOTED
        // filename may legitimately contain spaces, and trimming those
        // could merge two genuinely different sets, which is the unsafe
        // direction (Codex sweep 5, L8).
        let stem = match quoted {
            true => stem,
            false => stem.rsplit(char::is_whitespace).next().unwrap_or(stem),
        };
        if stem.is_empty() {
            // An anonymous set - a bare ".vol-01.par2" with no prefix -
            // cannot be name-capped itself, which is why it was skipped.
            // But it can still supply the GLOBAL block-size probe and
            // cap somebody else's set with a foreign block size, which
            // is the false-Impossible this detector exists to prevent.
            // Seeing one alongside any named stem is therefore already
            // two sets (Codex sweep 5, L2).
            anonymous = true;
            if !stems.is_empty() {
                return true;
            }
            continue;
        }
        if anonymous {
            return true;
        }
        if !stems.iter().any(|s| s == stem) {
            stems.push(stem.to_string());
            if stems.len() > 1 {
                return true;
            }
        }
    }
    false
}

/// Encoded bytes of every recovery volume the sweep did NOT prove absent
/// - the budget that actually exists on Usenet rather than the one the
/// NZB promises. Partial availability counts as fully present, the
/// conservative reading.
///
/// Paired with the slice count each volume's own name declares: both
/// halves of the ceiling [`measured_verdict`] builds, and merely counting
/// the rows answers the one question that needs no block size at all -
/// whether any recovery data is left standing.
fn live_volumes(nzb: &Nzb, absent_volumes: &[usize]) -> Vec<(u64, Option<usize>)> {
    // One question for the whole NZB, not one per volume: the cap is
    // only trustworthy when every volume here belongs to the set whose
    // block size sized it. See `multiple_par2_sets`.
    let cross_set = multiple_par2_sets(nzb);
    nzb.files
        .iter()
        .enumerate()
        .filter(|(fi, f)| f.kind() == FileKind::Par2Volume && !absent_volumes.contains(fi))
        .map(|(_, f)| {
            let declared = if cross_set {
                None
            } else {
                vol_count_from_name(f.filename_hint().unwrap_or(&f.subject))
            };
            (f.bytes(), declared)
        })
        .collect()
}

/// The payload files with a proven miss, paired with the NZB indexes
/// they came from.
///
/// The exact lengths that let a block grid be laid over them are not in
/// hand at this point - they ride out of the block-size probe - so
/// `length` is left unset and filled in afterwards. What IS in hand is
/// enough for [`block_size_could_condemn`] to decide whether that probe
/// is worth a round trip.
fn payload_damage(
    nzb: &Nzb,
    missing_segs: &std::collections::BTreeMap<usize, Vec<usize>>,
    counts_as_deficit: impl Fn(usize) -> bool,
) -> (Vec<usize>, Vec<FileDamage>) {
    let mut files = Vec::new();
    let mut damage = Vec::new();
    for (&fi, segs) in missing_segs {
        if !counts_as_deficit(fi) {
            continue;
        }
        files.push(fi);
        damage.push(FileDamage {
            seg_bytes: nzb.files[fi].segments.iter().map(|s| s.bytes).collect(),
            missing: segs.clone(),
            length: None,
        });
    }
    (files, damage)
}

/// What one finished sweep proves, reduced from the raw miss list.
///
/// Split out of `check`, which the placement floor, the proven-byte
/// deficit and the enabled-server filter together pushed past its
/// 500-line ceiling (TODO 106). A verbatim move, printing included: the
/// order of those per-file lines relative to the sweep is what the
/// operator reads, and every figure here derives from `missing` alone.
struct SweepFacts {
    missing_payload_bytes: u64,
    absent_volumes: Vec<usize>,
    absent_files: Vec<usize>,
    /// The same misses as segment indexes per file, ascending, so the
    /// escalation can PLACE them in the file's block grid.
    missing_segs: std::collections::BTreeMap<usize, Vec<usize>>,
    dropped: Vec<String>,
}

fn reduce_sweep(
    nzb: &Nzb,
    missing: &[usize],
    file_of: &[usize],
    seg_of: &[usize],
    sampled_of: &[usize],
    furniture: &[bool],
    counts_as_deficit: impl Fn(usize) -> bool,
) -> SweepFacts {
    let mut missing_files: std::collections::BTreeMap<usize, usize> = Default::default();
    // The same misses, kept as segment indexes rather than a tally, so
    // the escalation below can PLACE them in their file's block grid.
    let mut missing_segs: std::collections::BTreeMap<usize, Vec<usize>> = Default::default();
    for &i in missing {
        *missing_files.entry(file_of[i]).or_default() += 1;
        missing_segs.entry(file_of[i]).or_default().push(seg_of[i]);
    }
    // `placed_damage_floor` walks them in file order.
    for segs in missing_segs.values_mut() {
        segs.sort_unstable();
    }
    let mut dropped: Vec<String> = Vec::new();
    // Payload bytes no server has: the declared size of the sampled
    // segments the sweep PROVED missing, and nothing else. Bytes rather
    // than article counts because the block arithmetic below is in bytes
    // - an article is not a block, and on the 15 Aug post it was well
    // under half of one.
    //
    // It used to be the sampled miss RATE applied to the file's whole
    // size, which is an estimator with error in both directions and
    // averages by segment COUNT even when the segments differ in size -
    // yet `measured_verdict` consumes it as a FLOOR and can refuse the
    // job outright. 1,000 equal segments at a 10% sample with only the
    // head nuked: three real dead articles extrapolate to thirty, halve
    // to fifteen, and outrun a live 10-block budget. Summing the proven
    // segments makes it the lower bound the arithmetic already claimed
    // it was; SAMPLE_MARGIN stays on top as belt.
    let mut missing_payload_bytes: u64 = 0;
    for &i in missing {
        let fi = file_of[i];
        if counts_as_deficit(fi) {
            let seg = &nzb.files[fi].segments[seg_of[i]];
            missing_payload_bytes = missing_payload_bytes.saturating_add(seg.bytes);
        }
    }
    // Volumes every one of whose articles is missing everywhere. Only
    // reachable when the sweep took them whole; a partial sample can
    // never fill this list.
    let mut absent_volumes: Vec<usize> = Vec::new();
    // Every file whose sampled segments came back missing on every
    // server - the probe below will not waste a dial asking for one.
    let mut absent_files: Vec<usize> = Vec::new();
    for (fi, count) in &missing_files {
        let f = &nzb.files[*fi];
        let name = f.filename_hint().unwrap_or(&f.subject);
        let sampled = sampled_of[*fi];
        let whole = sampled > 0 && *count >= sampled;
        let note = if furniture[*fi] {
            " - metadata, not payload"
        } else if f.kind() == FileKind::Par2Volume {
            if whole {
                " - recovery volume, absent everywhere"
            } else {
                " - recovery volume"
            }
        } else {
            ""
        };
        println!(
            "  ✘ {name}: {count} of {sampled} sampled segment(s) missing on every server{note}"
        );
        if furniture[*fi] {
            dropped.push(name.to_string());
        }
        if whole {
            absent_files.push(*fi);
            if f.kind() == FileKind::Par2Volume {
                absent_volumes.push(*fi);
            }
        }
    }
    if !dropped.is_empty() {
        println!(
            "  note: metadata files are Usenet furniture the recovery set usually does \
             not cover, and pre-flight is STAT-only so it cannot read the set's file \
             list to be sure. Uncovered, the download completes and the file is \
             dropped; covered, repair rebuilds it from the same block budget."
        );
    }

    SweepFacts {
        missing_payload_bytes,
        absent_volumes,
        absent_files,
        missing_segs,
        dropped,
    }
}

pub(crate) async fn check(
    config: &Path,
    nzb_path: &Path,
    sample_pct: u8,
    connections: usize,
    window: usize,
    fast: bool,
) -> Result<Verdict> {
    use nzbkit::preflight::{
        AbortBudget, AbortRule, SweepPlan, stat_sweep_with, stratified_sample,
    };

    let mut cfg_all = Config::load(config)?;
    // Answer the question about the server set the DOWNLOADER will use.
    // `Config::load` keeps disabled rows (they stay configured and
    // testable) and `get::plan` drops them from the pool, so a preflight
    // over the unfiltered list dials an account the operator switched
    // off - a STAT sweep, and since the block-size probe landed, BODY
    // bytes too - and then lets that row's Have/Unknown cells block
    // `union_missing` from ever proving an article absent.
    cfg_all.servers.retain(|s| s.enabled);
    if cfg_all.servers.is_empty() {
        anyhow::bail!("every configured server is disabled, so pre-flight has nothing to ask");
    }
    let xml = std::fs::read(nzb_path).with_context(|| format!("reading {}", nzb_path.display()))?;
    let nzb = Nzb::parse(&xml).context("parsing NZB")?;

    // Recovery volumes ride the same sweep as the payload, but WHOLE
    // rather than sampled, and they never feed the deficit. Two
    // questions, one pass: the payload sample says how much is gone, and
    // the volume sweep says how much of the cure the NZB promises is
    // actually out there. Whole, because only a complete sweep can prove
    // a volume absent - four probes of a 37-segment volume coming back
    // missing says nothing about the other 33, and a budget struck off on
    // that evidence would be a false IMPOSSIBLE waiting to happen.
    //
    // The cap is what keeps a pathological recovery set from doubling
    // the sweep it rides on. Over it the volumes drop out of the sweep
    // entirely, exactly as before, and no volume is ever called absent -
    // the budget then stays the full NZB ceiling, which is the safe
    // direction.
    //
    // Proportional to the payload sample, not a flat number, because
    // the cost that matters is a RATIO and a flat one does not bound
    // it: 4,000 was under a tenth of a 3.2 GB post's volume segments
    // and a whole second sweep on a 15 GB one (+100%, measured 16 Aug),
    // while the STAT sweep is already the slow half of pre-flight - a
    // 100% sweep of the 15 Aug post cost 1,338 s across six servers.
    // Held to the sample, the sweep can never more than double for this
    // reason and on the one real post measured it grew by a fifth.
    //
    // What the cap gives up is narrow. A volume is struck off only when
    // EVERY segment of it was swept and missing everywhere, and on that
    // post every volume was partially available, so the extra 90 STATs
    // struck off nothing. In the case the whole sweep exists for - a
    // takedown that removes the parity with the payload - the payload
    // is gone too, so `measured_verdict` already fires by an order of
    // magnitude with no volume struck off at all. The band where being
    // over the cap changes the answer is only where the deficit falls
    // between the live volumes' ceiling and every volume's.
    let take_of = |n: usize| {
        if sample_pct >= 100 {
            n
        } else {
            ((n * sample_pct as usize).div_ceil(100)).max(2.min(n))
        }
    };
    let mut payload_sample = 0usize;
    let mut volume_segments = 0usize;
    for f in &nzb.files {
        if f.kind() == FileKind::Par2Volume {
            volume_segments += f.segments.len();
        } else {
            payload_sample += take_of(f.segments.len());
        }
    }
    let sweep_volumes = volume_segments <= payload_sample;

    // Sampled ids from DATA + par2-main files, whole ids from the
    // recovery volumes, + per-id weight = how many segments each sampled
    // id represents in its file.
    let mut ids: Vec<String> = Vec::new();
    let mut weights: Vec<f64> = Vec::new();
    let mut file_of: Vec<usize> = Vec::new();
    // Which SEGMENT each probe asked about, not just which file. Two
    // things need it: the damage floor is the sum of the `bytes=` of the
    // segments the sweep actually PROVED missing (see
    // `missing_payload_bytes` below), and a miss can only be PLACED in
    // the file's block grid if we know which segment it was (see
    // `FileDamage`). Neither is recoverable from the file index alone.
    let mut seg_of: Vec<usize> = Vec::new();
    let mut sampled_of: Vec<usize> = vec![0; nzb.files.len()];
    for (fi, f) in nzb.files.iter().enumerate() {
        let is_volume = f.kind() == FileKind::Par2Volume;
        if is_volume && !sweep_volumes {
            continue;
        }
        let n = f.segments.len();
        let take = if is_volume { n } else { take_of(n) };
        for si in stratified_sample(n, take) {
            ids.push(format!("<{}>", f.segments[si].message_id));
            weights.push(n as f64 / take as f64);
            file_of.push(fi);
            seg_of.push(si);
            sampled_of[fi] += 1;
        }
    }
    // Which NZB files are furniture rather than payload. Only DATA files
    // qualify: a `Par2Volume` is budget rather than deficit, and
    // `Par2Main` is the packet repair is made of, not something to shrug
    // off.
    let furniture: Vec<bool> = nzb
        .files
        .iter()
        .map(|f| {
            f.kind() == FileKind::Data
                && is_droppable_metadata(f.filename_hint().unwrap_or(&f.subject))
        })
        .collect();
    // Recovery volumes are in the sweep now, so the deficit has to say
    // out loud what it always meant: payload only. Counting a volume
    // here would charge the budget's own absence to the damage it is
    // supposed to repair.
    let counts_as_deficit =
        |fi: usize| nzb.files[fi].kind() != FileKind::Par2Volume && !furniture[fi];
    // Known counts sum; an ordinal-only volume (`.vol-NN.par2`) has real
    // blocks this name cannot size, so it is recorded as UNKNOWN rather
    // than silently added as zero - see `verdict_of`.
    let mut recovery: usize = 0;
    let mut recovery_unknown = false;
    // Per-file, so the sweep can strike a volume's blocks off again once
    // it has PROVED that volume absent - see the subtraction below.
    let mut vol_count_of: Vec<usize> = vec![0; nzb.files.len()];
    for (fi, f) in nzb
        .files
        .iter()
        .enumerate()
        .filter(|(_, f)| f.kind() == FileKind::Par2Volume)
    {
        match vol_count_from_name(f.filename_hint().unwrap_or(&f.subject)) {
            // Saturating, not `+=`: the count comes from a filename in
            // a file we were handed, and a budget that wraps is worse
            // than one that pegs. `par2_vol_count` caps the per-volume
            // figure; this keeps the sum honest even if that cap is
            // ever raised (14 Aug sweep).
            Some(n) => {
                recovery = recovery.saturating_add(n);
                vol_count_of[fi] = n;
            }
            None => recovery_unknown = true,
        }
    }
    println!(
        "pre-flight: STAT {} article(s) ({}% sample) × {} server(s), {} conns × window {}",
        ids.len(),
        sample_pct.min(100),
        cfg_all.servers.len(),
        connections,
        window
    );

    // The probe, moved in FRONT of the sweep on the one shape that
    // needs it there.
    //
    // `recovery_unknown` falls out of filenames alone, before a byte
    // leaves the machine, and it is exactly the shape whose abort could
    // not be armed: the budget is uncountable, so there was no number to
    // stop against, and the post that most needed a fast abort was the
    // only one that could not have one. Measured 15 Aug: the healthy
    // post went 119 s -> 3.9-7.1 s while the dead one went 144 s ->
    // 156-163 s, SLOWER than its own baseline, because it paid for a
    // full sweep and then a probe.
    //
    // Reading the block size first costs one BODY - 41,901 bytes on that
    // post, well under a second - and turns the budget into a ceiling
    // the sweep can stop against. It is gated twice over: only when
    // names leave the budget unsizable, and only in the profile that has
    // an abort to arm. The report's profile sweeps exhaustively by
    // design and would spend the probe for nothing, so it keeps the late
    // one, which has the sweep's own answers to skip par2 files Usenet
    // no longer has.
    let (probed_early, probe_tried) = if fast && recovery_unknown {
        block_size_probe(&cfg_all.servers, &nzb, &[]).await
    } else {
        (None, Vec::new())
    };

    // `fast` is the daemon's profile, and both of its shortcuts are
    // licensed by `union_missing` needing Missing on EVERY server. The
    // first Have settles an article, so the servers behind it skip it -
    // measured 15 Aug as 5/6 of a healthy post's queries, and a miss
    // costs 9-31x a hit on five of the six providers in a measured
    // six-server config, which is where the sweep's whole wall time went.
    //
    // Only the payload is the deficit, whichever units it is counted in.
    // A recovery volume is budget, and furniture is neither (#23), so
    // neither may ever trip the abort.
    //
    // Both budgets are CEILINGS no later evidence can raise, which is
    // what makes an abort armed on them conservative:
    //
    // - The counted one sums the slice counts every volume name
    //   declares. Absent volumes are struck off AFTER the sweep, so the
    //   budget the verdict finally uses is at most this one.
    // - The measured one sums `max_recovery_blocks` over every volume
    //   the NZB carries with NONE struck off - striking one off needs a
    //   sweep that has not run yet, and can only make the final ceiling
    //   smaller.
    //
    // A deficit that clears either clears what the verdict will use. And
    // an abort cannot invent a verdict in any case: the verdict is
    // recomputed from the finished matrix below, and a sweep cut short
    // has strictly fewer articles proved missing everywhere.
    // Asked once for the whole NZB and shared by both ceilings below,
    // so the abort and the verdict cannot disagree about whether a
    // declared count may be trusted.
    let cross_set_par2 = multiple_par2_sets(&nzb);
    let plan = if fast {
        let abort = if recovery_unknown {
            probed_early
                .as_ref()
                .map(|p| p.block_size)
                .map(|block_size| AbortBudget {
                    // Bytes, because that is what the measured route
                    // weighs - and the SEGMENT's own declared bytes, which
                    // is the identical quantity `missing_payload_bytes`
                    // sums below, id by id.
                    //
                    // It used to be `file.bytes() / sampled_of[fi]`: the
                    // share of the whole file each sampled id stood for.
                    // That is an EXTRAPOLATION, and it silently broke the
                    // invariant three doc blocks in this file claim - that
                    // an abort cannot cost the post its measured verdict.
                    // At the shipped 10% sample it charged each proven miss
                    // ten times what the verdict would count, so the sweep
                    // stopped after ~9 misses on a deficit the verdict then
                    // recomputed as ~9 MiB and called repairable, where the
                    // full 100-article sample would have condemned the
                    // post. Weighing exactly what the verdict sums is the
                    // whole fix; it can only ever DELAY an abort, never
                    // manufacture one.
                    weights: file_of
                        .iter()
                        .zip(seg_of.iter())
                        .map(|(&fi, &si)| {
                            if counts_as_deficit(fi) {
                                nzb.files[fi].segments[si].bytes as f64
                            } else {
                                0.0
                            }
                        })
                        .collect(),
                    rule: AbortRule::Blocks {
                        block_size,
                        // The same margin the verdict will apply, from the
                        // same helper, so the two cannot drift - and it
                        // matters more here than it does there. An abort
                        // armed pre-sweep leans on a deficit that is still
                        // arriving, so the discount for how much of it came
                        // off a sample rather than a census is what keeps
                        // the standing-down conservative.
                        margin: sample_margin(sample_pct),
                        ceiling: nzb
                            .files
                            .iter()
                            .filter(|f| f.kind() == FileKind::Par2Volume)
                            .map(|f| {
                                // Capped where the name declares a
                                // count, exactly as `measured_verdict`
                                // caps it - the two ceilings must agree
                                // or the abort could stand down on a
                                // budget the verdict then reads larger.
                                // Which means this must decline the cap
                                // on the same condition `live_volumes`
                                // declines it, or they disagree in the
                                // one case that matters.
                                let by_bytes =
                                    nzbkit::par2::max_recovery_blocks(f.bytes(), block_size);
                                if cross_set_par2 {
                                    return by_bytes;
                                }
                                match vol_count_from_name(f.filename_hint().unwrap_or(&f.subject)) {
                                    Some(n) => by_bytes.min(n as u64),
                                    None => by_bytes,
                                }
                            })
                            .fold(0u64, u64::saturating_add),
                    },
                })
        } else {
            // No block size, and no probe spent going to get one: this
            // shape declares its counts, so it never reaches the
            // pre-sweep probe above, and a healthy post must keep
            // spending nothing. Same weights, against the volumes' own
            // encoded bytes - the block-size-free form of the rule
            // above, and deliberately the same comparison
            // `block_size_could_condemn` makes after the sweep, so a
            // stand-down cannot cost the post its measured verdict.
            Some(AbortBudget {
                // Segment bytes, not a file-wide share - see the twin
                // above for why the extrapolated form was wrong.
                weights: file_of
                    .iter()
                    .zip(seg_of.iter())
                    .map(|(&fi, &si)| {
                        if counts_as_deficit(fi) {
                            nzb.files[fi].segments[si].bytes as f64
                        } else {
                            0.0
                        }
                    })
                    .collect(),
                rule: AbortRule::Bytes {
                    margin: sample_margin(sample_pct),
                    ceiling_bytes: nzb
                        .files
                        .iter()
                        .filter(|f| f.kind() == FileKind::Par2Volume)
                        .map(|f| f.bytes())
                        .fold(0u64, u64::saturating_add),
                },
            })
        };
        SweepPlan {
            connections,
            window,
            settle_on_have: true,
            abort_over: abort,
        }
    } else {
        SweepPlan::full(connections, window)
    };
    let sweep = stat_sweep_with(&cfg_all.servers, &ids, &plan).await;
    // A sweep that skips questions cannot make a per-server availability
    // claim: a server asked 10% of them is not 10% available. So the
    // fast profile does not print one.
    if !fast {
        for (si, s) in cfg_all.servers.iter().enumerate() {
            let (have, missing, unknown) = sweep.server_counts(si);
            println!(
                "  {:<28} {:>5.1}% available ({have} have, {missing} missing{})",
                s.host,
                have as f64 * 100.0 / ids.len().max(1) as f64,
                if unknown > 0 {
                    format!(", {unknown} unknown")
                } else {
                    String::new()
                }
            );
        }
        print_sweep_timing(&sweep, &cfg_all.servers);
    }

    let missing = sweep.union_missing();
    let est_missing: f64 = missing
        .iter()
        .filter(|&&i| counts_as_deficit(file_of[i]))
        .map(|&i| weights[i])
        .sum();
    let est_missing = est_missing.round() as usize;
    let SweepFacts {
        missing_payload_bytes,
        absent_volumes,
        absent_files,
        missing_segs,
        dropped,
    } = reduce_sweep(
        &nzb,
        &missing,
        &file_of,
        &seg_of,
        &sampled_of,
        &furniture,
        counts_as_deficit,
    );
    // Blocks the NZB promises that Usenet cannot deliver are not a
    // budget. The counted budget above is summed from every
    // `.volNN+MM.par2` NAME before the sweep runs, so a volume the sweep
    // then proves absent on every server still had its declared blocks
    // spent on the verdict: one absent `.vol000+10.par2` beside five
    // missing payload articles read "5 <= 10, repairable" with no live
    // parity at all. The measured route already strikes these off (it
    // sizes only `live` below); the counted route was left behind, and
    // the comment on the abort budget above already assumed otherwise.
    //
    // Only WHOLLY absent volumes, which is what `absent_volumes` means:
    // it needs a complete sweep of the volume with every article missing
    // on every server, and `union_missing` reads Unknown as available -
    // so a partial sample or an undialled server can never strike a
    // volume off.
    for fi in &absent_volumes {
        recovery = recovery.saturating_sub(vol_count_of[*fi]);
    }

    // Verdict in article units (block ≈ article for typical posts; the
    // live ledger is exact once the par2 main packet is in hand), and in
    // PAYLOAD articles only - see verdict_of.
    let live = live_volumes(&nzb, &absent_volumes);
    let live_bytes: Vec<u64> = live.iter().map(|&(b, _)| b).collect();
    let (damage_files, mut damage) = payload_damage(&nzb, &missing_segs, counts_as_deficit);

    // Verdict in PAYLOAD articles, and deliberately not a comparison: an
    // article is not a block, so the counted budget can frame the answer
    // but never condemn on it. Only an empty budget condemns here - see
    // verdict_of.
    let mut verdict = verdict_of(est_missing, recovery, recovery_unknown, live.len(), dropped);

    // The escalation, from any REPAIRABLE a block size could actually
    // move, and `block_size_could_condemn` is the whole gate.
    //
    // It used to sit behind `est_missing > recovery` as well, which was
    // the comparison deciding the verdict outright before 16 Aug. That
    // condition is not merely redundant here, it is wrong in both
    // directions: it fires on posts a block size could never condemn
    // (the counted budget is ZERO on every `.vol-NN.par2` set, so one
    // missing article satisfies it), and it stays quiet on posts whose
    // blocks are so much larger than their articles that the count reads
    // as comfortable while the bytes do not. The pre-gate asks the
    // measured question itself, divided through by the block size, so it
    // is right in both.
    //
    // A COST gate and nothing more - what it guards is one article on
    // the wire, and what it decides is only whether to ask. A healthy
    // post never trips it and spends nothing, which is what lets
    // pre-flight be left on.
    if let Verdict::Repairable { dropped, .. } = &verdict
        && block_size_could_condemn(missing_payload_bytes, sample_pct, &live_bytes, &damage)
    {
        // Already in hand when the sweep was armed from it, and paying
        // for the same article twice is the whole defect this ordering
        // exists to fix. The late probe still runs when there was no
        // early one (the report's profile), and when the early one drew
        // the two par2 files the sweep has since proved absent
        // everywhere - the one failure a second, now informed, attempt
        // can actually fix. An early probe that failed for any other
        // reason - server unreachable, no verifiable Main packet in an
        // article that IS there - would fail again for the same reason,
        // so it is not re-asked.
        //
        // Only the LATE probe can carry `block_size_could_condemn`: that
        // gate weighs the damage against the live volume bytes, and
        // neither number exists before the sweep. So the early probe
        // spends its one BODY unconditionally, which is the trade this
        // ordering makes - one article on an unsizable post that turns
        // out healthy, against the ~100 s it saves when the same shape
        // is dead.
        let mut probe_ran = !probe_tried.is_empty();
        let probed = match probed_early {
            Some(p) => Some(p),
            None if probe_tried.iter().all(|fi| absent_files.contains(fi)) => {
                probe_ran = true;
                block_size_probe(&cfg_all.servers, &nzb, &absent_files)
                    .await
                    .0
            }
            None => None,
        };
        match probed {
            Some(probed) => {
                // Only now can the grid be laid, and only over the files
                // the fetched packets actually described. An undescribed
                // file keeps the byte figure and nothing more, because a
                // probe that read no FileDesc has learnt nothing about
                // whether the set covers that file.
                for (d, &fi) in damage.iter_mut().zip(&damage_files) {
                    d.length = nzb.files[fi]
                        .filename_hint()
                        .and_then(|n| probed.described_length(n));
                }
                match measured_verdict(
                    missing_payload_bytes,
                    sample_pct,
                    probed.block_size,
                    &live,
                    absent_volumes.len(),
                    &damage,
                    dropped.clone(),
                ) {
                    Some(v) => verdict = v,
                    // Worth a line of its own: the counted budget looked
                    // short and the measured one is not, which is the
                    // whole reason this route stopped condemning posts
                    // on counts.
                    None => println!(
                        "  note: the recovery set's blocks are {}, and the payload no \
                         server has cannot damage more of them than the volumes can \
                         still deliver",
                        block_size_label(probed.block_size)
                    ),
                }
            }
            // Only when a probe actually went and looked. A pre-gate
            // that declined to look has nothing to report.
            None if probe_ran => println!(
                "  note: could not read a PAR2 main packet, so the recovery volumes \
                 whose names declare no slice count stay unsized"
            ),
            None => {}
        }
    }
    report_verdict(&verdict, sweep.elapsed);
    Ok(verdict)
}

/// The human report's last line: the verdict, in the units it was
/// actually reached in, with the metadata it set aside named rather
/// than folded into a number.
///
/// Lifted out of [`check`] on 16 Aug because that function went over
/// the size gate, and it is the right seam: everything above it gathers
/// evidence, and this is the one place that turns the answer into
/// English. Which sentence a REPAIRABLE gets is decided here rather
/// than by the caller, because the three differ only in what the sweep
/// could not establish - see the arms.
fn report_verdict(verdict: &Verdict, elapsed: std::time::Duration) {
    let dropped_tail = |dropped: &[String]| {
        if dropped.is_empty() {
            String::new()
        } else {
            format!(
                "; {} metadata file(s) no server has in full: {}",
                dropped.len(),
                dropped.join(", ")
            )
        }
    };
    match &verdict {
        Verdict::Complete { dropped } if dropped.is_empty() => println!(
            "verdict: COMPLETE - every sampled article present on at least one server ({:.2?})",
            elapsed
        ),
        Verdict::Complete { dropped } => println!(
            "verdict: COMPLETE - the payload is whole{} ({:.2?})",
            dropped_tail(dropped),
            elapsed
        ),
        Verdict::Repairable {
            est_missing,
            recovery,
            recovery_unknown: false,
            dropped,
        } if est_missing <= recovery => println!(
            "verdict: REPAIRABLE - ≈{est_missing} payload article(s) missing everywhere ≤ {recovery} recovery block(s){} ({:.2?})",
            dropped_tail(dropped),
            elapsed
        ),
        // The deficit outruns the counted budget and every volume
        // declares its count - so the two numbers below are in different
        // units, and the report prints them side by side rather than
        // subtracting one from the other. An article is only a block on
        // posts where the poster made it one. Which of the two ways this
        // was reached - the block size unreadable, or read and the post
        // cleared by it - is the note above's to say.
        Verdict::Repairable {
            est_missing,
            recovery,
            recovery_unknown: false,
            dropped,
        } => println!(
            "verdict: PROBABLY REPAIRABLE - ≈{est_missing} payload article(s) missing everywhere against {recovery} declared recovery block(s) - an article is not a block, and the comparison that decides this is made on blocks, during repair{} ({:.2?})",
            dropped_tail(dropped),
            elapsed
        ),
        Verdict::Repairable {
            est_missing,
            recovery,
            recovery_unknown: true,
            dropped,
        } => println!(
            "verdict: PROBABLY REPAIRABLE - ≈{est_missing} payload article(s) missing everywhere, against {recovery} counted recovery block(s) plus volumes whose names do not say how many they hold - the real block count is read during repair{} ({:.2?})",
            dropped_tail(dropped),
            elapsed
        ),
        Verdict::Impossible {
            est_missing,
            recovery,
            measured,
            dropped,
        } => println!(
            "verdict: IMPOSSIBLE - {}{}{} ({:.2?})",
            impossible_reason(*est_missing, *recovery, measured),
            match measured {
                Some(m) if m.absent_volumes > 0 => format!(
                    "; {} recovery volume(s) are on no server and hold nothing for us",
                    m.absent_volumes
                ),
                _ => String::new(),
            },
            dropped_tail(dropped),
            elapsed
        ),
    }
}

/// `NZBFAST_PREFLIGHT_TIMING=1`: add the per-connection rows to the
/// timing report. The per-server summary above them always prints from
/// the human report; the daemon's profile prints neither, because it
/// runs pre-flight on every job and seven lines each is a flood.
fn preflight_timing_wanted() -> bool {
    std::env::var("NZBFAST_PREFLIGHT_TIMING").is_ok_and(|v| v != "0")
}

/// Where a sweep's wall time actually went, per server.
///
/// The sweep runs every server at once, so its cost is the SLOWEST
/// server's leg and nothing else: five servers finishing in two seconds
/// are invisible behind a sixth that takes two minutes, and dividing the
/// total by the sample invents a per-STAT cost that no server charges.
/// Splitting reply latency by what the reply SAID is what made the real
/// model visible - a miss costs 9-31x a hit on five of six live
/// providers, so cost tracks the MISS count, not the STAT count. A
/// single median over both just reports the post's miss ratio.
pub(crate) fn print_sweep_timing(sweep: &SweepResult, servers: &[nzbkit::config::ServerConfig]) {
    if sweep.legs.is_empty() {
        return;
    }
    let detail = preflight_timing_wanted();
    println!(
        "  timing (sweep total {:.2?} = the slowest server):",
        sweep.elapsed
    );
    for (si, s) in servers.iter().enumerate() {
        let legs: Vec<&LegStats> = sweep.legs.iter().filter(|l| l.server == si).collect();
        let Some(slowest) = legs.iter().max_by_key(|l| l.total) else {
            continue;
        };
        let recv: usize = legs.iter().map(|l| l.recv).sum();
        let skipped: usize = legs.iter().map(|l| l.skipped).sum();
        let rate: f64 = legs.iter().map(|l| l.stats_per_sec()).sum();
        let dial = legs.iter().map(|l| l.connect).max().unwrap_or_default();
        // An outcome other than Done is why a row is short, so it is
        // named rather than left to be inferred from the count.
        let mut bad: Vec<String> = legs
            .iter()
            .filter(|l| l.outcome != LegOutcome::Done)
            .map(|l| format!("c{} {:?}@{}", l.conn, l.outcome, l.recv))
            .collect();
        bad.sort();
        println!(
            "    {:<28} {:>7.2?} slowest leg (dial {:>6.2?}), {recv} replies ({skipped} skipped), \
{rate:>6.1}/s, HIT p50 {:>7.1}ms p90 {:>7.1}ms | MISS p50 {:>7.1}ms p90 {:>7.1}ms{}",
            s.host,
            slowest.total,
            dial,
            slowest.hit_pct_ms(50),
            slowest.hit_pct_ms(90),
            slowest.miss_pct_ms(50),
            slowest.miss_pct_ms(90),
            if bad.is_empty() {
                String::new()
            } else {
                format!("  [{}]", bad.join(", "))
            }
        );
        if detail {
            for l in legs {
                println!(
                    "      c{:<2} {:>4}/{:<4} recv  dial {:>6.2?}  first {:>7.1}ms  total {:>7.2?}  \
hit n={:<5} p50 {:>7.1} p90 {:>7.1}  miss n={:<5} p50 {:>7.1} p90 {:>7.1}ms  {:?}",
                    l.conn,
                    l.recv,
                    l.assigned,
                    l.connect,
                    l.first_reply.unwrap_or_default().as_secs_f64() * 1000.0,
                    l.total,
                    l.hit_us.len(),
                    l.hit_pct_ms(50),
                    l.hit_pct_ms(90),
                    l.miss_us.len(),
                    l.miss_pct_ms(50),
                    l.miss_pct_ms(90),
                    l.outcome,
                );
            }
        }
    }
}

/// The `check` subcommand. `fast` takes the daemon's profile - see the
/// `fast` branch in [`check`] - instead of the human report.
pub(crate) async fn run_check(
    config: &Path,
    nzb: &Path,
    sample: u8,
    connections: usize,
    window: usize,
    fast: bool,
) -> Result<()> {
    let t0 = std::time::Instant::now();
    let verdict = check(config, nzb, sample, connections, window, fast).await?;
    if fast {
        match &verdict {
            Verdict::Impossible {
                est_missing,
                recovery,
                measured,
                ..
            } => println!(
                "verdict: IMPOSSIBLE - {} ({:.2?})",
                impossible_reason(*est_missing, *recovery, measured),
                t0.elapsed()
            ),
            _ => println!(
                "verdict: not impossible - this job would be downloaded ({:.2?})",
                t0.elapsed()
            ),
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "check_tests.rs"]
mod check_tests;
