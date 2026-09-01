//! The two largest leaf blocks of the pre-flight `check` command: the
//! sweep plan it arms before asking, and the measured escalation it runs
//! after. Hoisted out of `check.rs` verbatim on 22 Aug 2026 because
//! `fn check` sat at exactly the size gate's 500-line function ceiling,
//! so the next line anyone added would have reddened main (TODO 106
//! pattern, as `check_tests.rs` and `extract/names.rs`). Behaviour
//! unchanged: this is `check`'s own child module, glob-imported back, so
//! callers and the helpers it leans on are exactly as they were.

use super::*;
use nzbkit::preflight::{AbortBudget, AbortRule, ProbedSet, SweepPlan};

/// The sweep plan `check` hands to `stat_sweep_with`: the report's
/// exhaustive one, or the daemon's fast profile with its abort budget
/// armed from whichever ceiling the NZB's names (or an early probe)
/// could size.
///
/// Hoisted out of [`check`] verbatim on 22 Aug 2026 when that function
/// sat at exactly the size gate's 500-line ceiling; behaviour unchanged.
/// The comment block that opens the body is the one that used to sit
/// over `let plan = ...` in `check`, and every "below" in it still
/// points at `check`.
pub(super) fn sweep_plan(
    nzb: &Nzb,
    fast: bool,
    sample_pct: u8,
    connections: usize,
    window: usize,
    recovery_unknown: bool,
    probed_early: Option<&ProbedSet>,
    file_of: &[usize],
    seg_of: &[usize],
    counts_as_deficit: impl Fn(usize) -> bool,
) -> SweepPlan {
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
    let cross_set_par2 = multiple_par2_sets(nzb);
    if fast {
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
                                match vol_count_from_name(f.classify().name()) {
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
    }
}

/// The measured escalation: from a REPAIRABLE the counted budget could
/// not decide, spend (at most) one BODY on the set's PAR2 Main packet
/// and let block arithmetic have the last word.
///
/// Hoisted out of [`check`] verbatim on 22 Aug 2026 alongside
/// [`sweep_plan`]; behaviour unchanged. `verdict` is rewritten in place
/// exactly where `check` used to assign it, and `damage` is annotated
/// with the described lengths the same way.
pub(super) async fn escalate_repairable(
    servers: &[nzbkit::config::ServerConfig],
    nzb: &Nzb,
    verdict: &mut Verdict,
    probed_early: Option<ProbedSet>,
    probe_tried: &[usize],
    absent_files: &[usize],
    absent_volumes: usize,
    missing_payload_bytes: u64,
    sample_pct: u8,
    live: &[(u64, Option<usize>)],
    damage_files: &[usize],
    damage: &mut [FileDamage],
) {
    let live_bytes: Vec<u64> = live.iter().map(|&(b, _)| b).collect();
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
    if let Verdict::Repairable { dropped, .. } = &*verdict
        && block_size_could_condemn(missing_payload_bytes, sample_pct, &live_bytes, damage)
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
                block_size_probe(servers, nzb, absent_files).await.0
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
                for (d, &fi) in damage.iter_mut().zip(damage_files) {
                    d.length = nzb.files[fi]
                        .filename_hint()
                        .and_then(|n| probed.described_length(n));
                }
                match measured_verdict(
                    missing_payload_bytes,
                    sample_pct,
                    probed.block_size,
                    live,
                    absent_volumes,
                    damage,
                    dropped.clone(),
                ) {
                    Some(v) => *verdict = v,
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
}
