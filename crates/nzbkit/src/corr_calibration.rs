//! Calibration harness for the pre-feed correlation tiers.
//!
//! The unit tests in [`crate::predb_corr`] pin individual score bands and
//! the index tests in [`crate::index`] pin individual gates. Neither
//! answers the question that actually matters: over a POPULATION, what
//! fraction of the names correlation applies are right, and what
//! fraction of the right pairs does it find?
//!
//! That is what this module measures. It builds a synthetic corpus whose
//! true pairing is known by construction - clean pairs, slow pairs,
//! crowded windows, REPACK siblings, wrong-kind decoys - runs the real
//! release-driven walk over it, and asserts precision and recall FLOORS
//! per tier. A constants tweak that widens a band, softens the margin or
//! loosens a veto shows up here as a failing floor instead of shipping.
//!
//! The floors are set below the measured values with deliberate slack, so
//! this fails on a degradation, not on a rounding difference. When a
//! change legitimately moves a number, move the floor in the same commit
//! and say why - that edit is the calibration record.
//!
//! A floor is only as good as the population under it: see the
//! `Calib.Filler` rows in `run_corpus` for a clause this harness
//! asserted for a month without ever exercising it.
//!
//! Design reference: `research/DESIGN-predb-phase2-correlation-2026-08.md`
//! section 5, "Calibration regression".

use crate::index::Index;
use crate::nntp::OverEntry;
use crate::predb::{PreKind, PreLine};

/// A release the corpus knows the true answer for.
struct Pair {
    /// The pre title this release genuinely is.
    truth: String,
    stem: String,
    /// What the corpus expects of the auto tier for this pair.
    class: Class,
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
enum Class {
    /// Sized, tight, fast, uncontested: the shape auto exists for.
    CleanFast,
    /// Sized and tight but slow: a suggestion, never automatic.
    Slow,
    /// A different release of the same size in the same window.
    Crowded,
    /// A REPACK of the same title in the same window.
    Sibling,
    /// A clean pair whose candidate window is stuffed past CAND_LIMIT
    /// with size-IMPLAUSIBLE pres (R2/E1 harness gap 1, release side).
    /// Before the corr_eval size prefilter this read `saturated` and
    /// auto failed closed on a false signal; with the prefilter the
    /// noise never enters the window and the pair auto-applies. This
    /// class is what makes that lift a VISIBLE recall number: revert
    /// the prefilter and the auto-recall floor fails.
    FloodedWindow,
    /// A clean pair whose PRE's forward window holds >= CORR_WINDOW
    /// size-PLAUSIBLE releases (R2/E1 harness gap 1, pre side). The
    /// mutual-best gate cannot prove a maximum over a truncated sample,
    /// so it fails closed: suggestion, never auto. The decoys sit well
    /// inside every band ever proposed ([0.90, 1.15]x wire), so a
    /// future ratio-band narrowing alone cannot un-saturate this
    /// window - the class pins the fail-closed behaviour itself.
    ForwardCrowded,
    /// The same release posted twice by the same poster (byte-exact
    /// crosspost, R2 harness gap 2). Under today's gate the twin is
    /// counted as a competitor, the margin self-vetoes, and the pair is
    /// suggestion-only - a RECALL loss this class makes visible. A
    /// tight twin collapse (byte-exact + same poster, R2 option 3)
    /// would flip this class to auto; whoever ships it must move this
    /// expectation and the floors in that commit, with the rationale.
    TwinCrosspost,
    /// A DIFFERENT-poster release at near-identical size and time (the
    /// 6,703-pair coincidence population R2 measured, vs 31 genuine
    /// same-poster reposts). It must suppress auto on the true pair
    /// (margin) and must NEVER be named itself. A LOOSE twin key
    /// (size+time, poster-blind) would collapse the true pair out of
    /// this decoy's mutual-best window and auto-apply the pre's name to
    /// the WRONG release - that regression fails the 1.0 precision
    /// floor here.
    TwinCoincidence,
}

/// Deterministic stem generator. No `rand` dependency, and the same
/// corpus every run - a calibration number that moved must be the code's
/// doing, not the seed's.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        // Numerical Recipes' 64-bit LCG constants.
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        self.0 >> 11
    }

    /// An obfuscated-looking stem: mixed case with digits, never two
    /// digits adjacent (a 4-digit run would parse as a year and stop
    /// `junk_score` calling the stem obfuscated at all).
    fn stem(&mut self) -> String {
        const LO: &[u8] = b"abcdefghijkmnpqrstuvwxyz";
        const UP: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
        const DI: &[u8] = b"23456789";
        let mut s = String::with_capacity(24);
        for i in 0..24 {
            let r = self.next() as usize;
            let c = match i % 4 {
                0 | 2 => LO[r % LO.len()],
                1 => UP[r % UP.len()],
                _ => DI[r % DI.len()],
            };
            s.push(c as char);
        }
        s
    }
}

/// A title-only pre: a name, a section, a size. What the live public
/// relays actually carry.
fn pre(title: &str, size: u64, pt: i64) -> PreLine {
    PreLine {
        kind: PreKind::New,
        title: title.into(),
        category: "X264-HD".into(),
        size,
        date: pt,
        source: "CALIB".into(),
        ..Default::default()
    }
}

fn over(stem: &str, bytes: u64, posted: i64) -> OverEntry {
    over_as(stem, "poster@calib", bytes, posted)
}

/// Same, with the poster in hand - the twin classes are ABOUT poster
/// identity, so the corpus has to be able to vary it.
fn over_as(stem: &str, from: &str, bytes: u64, posted: i64) -> OverEntry {
    OverEntry {
        number: 0,
        subject: format!("\"{stem}.part01.rar\" yEnc (1/1)"),
        from: from.into(),
        message_id: format!("<{stem}@calib>"),
        bytes,
        date: posted,
    }
}

/// Wire bytes that decode to `content` bytes of yEnc payload, so the
/// scorer's estimate lands on the announced size.
fn wire(content: u64) -> u64 {
    (content as f64 * crate::predb_corr::YENC_FACTOR) as u64
}

/// Content sizes spanning the classes the feed actually announces, from
/// a 720p episode to a UHD BluRay remux.
const SIZES: [u64; 6] = [
    1_400_000_000,
    2_600_000_000,
    6_000_000_000,
    14_000_000_000,
    28_000_000_000,
    46_000_000_000,
];

/// Post-minus-pre seconds. The four fast values sit in the T=40/T=34
/// bands (auto-eligible with a tight size); the slow ones do not, by
/// design. The slow values are spread across the 6 h, 24 h and 3 d
/// buckets on purpose: a T band with no corpus case in it is a band this
/// harness cannot see flattened.
const FAST_DELTAS: [i64; 4] = [300, 1_500, 3_000, 6_500];
const SLOW_DELTAS: [i64; 3] = [20_000, 50_000, 100_000];

/// 20 days between pairs: longer than [`crate::predb_corr::DELTA_MAX`],
/// so a pair's window holds only the decoys the corpus deliberately puts
/// there. Crowding is a property under test, not an accident of layout.
const SPACING: i64 = 20 * 86_400;
const EPOCH: i64 = 1_700_000_000;

const N_CLEAN: usize = 72;
const N_SLOW: usize = 12;
const N_CROWDED: usize = 12;
const N_SIBLING: usize = 12;
const N_FLOODED: usize = 4;
const N_FWDCROWD: usize = 2;
const N_TWINX: usize = 6;
const N_TWINC: usize = 6;
const N_PAIRS: usize =
    N_CLEAN + N_SLOW + N_CROWDED + N_SIBLING + N_FLOODED + N_FWDCROWD + N_TWINX + N_TWINC;

/// Noise pres per FloodedWindow pair: past `corr_eval`'s CAND_LIMIT
/// (4000), so the un-prefiltered window is provably saturated.
const FLOOD_PRES: usize = 4_100;
/// Decoy releases per ForwardCrowded pair: past CORR_WINDOW (200), so
/// the pre-side window is provably saturated.
const FWD_DECOYS: usize = 205;
/// Non-pair release rows the corpus adds (the backlog walks these too):
/// the forward-window decoys, one crosspost twin row per TwinCrosspost
/// pair, one coincidence decoy row per TwinCoincidence pair.
const N_EXTRA_RELEASES: usize = N_FWDCROWD * FWD_DECOYS + N_TWINX + N_TWINC;

/// Build the corpus and run the real release-driven walk over it with the
/// auto tier on. Returns (pairs, decoy release stems, applied names by
/// stem, suggested names by stem).
#[expect(clippy::type_complexity)]
fn run_corpus(
    ix: &mut Index,
) -> (
    Vec<Pair>,
    Vec<String>,
    std::collections::HashMap<String, String>,
    std::collections::HashMap<String, (String, String)>,
) {
    let mut rng = Lcg(0x5EED_C0FF_EE12_3456);
    let mut pairs: Vec<Pair> = Vec::with_capacity(N_PAIRS);
    let mut lines: Vec<PreLine> = Vec::new();
    let mut entries: Vec<(String, OverEntry)> = Vec::new();
    // Release rows that are not pairs: forward-window decoys and the
    // coincidence twins. They have no truth; ANY name applied to one is
    // a precision failure.
    let mut decoys: Vec<String> = Vec::new();

    for i in 0..N_PAIRS {
        let class = if i < N_CLEAN {
            Class::CleanFast
        } else if i < N_CLEAN + N_SLOW {
            Class::Slow
        } else if i < N_CLEAN + N_SLOW + N_CROWDED {
            Class::Crowded
        } else if i < N_CLEAN + N_SLOW + N_CROWDED + N_SIBLING {
            Class::Sibling
        } else if i < N_CLEAN + N_SLOW + N_CROWDED + N_SIBLING + N_FLOODED {
            Class::FloodedWindow
        } else if i < N_CLEAN + N_SLOW + N_CROWDED + N_SIBLING + N_FLOODED + N_FWDCROWD {
            Class::ForwardCrowded
        } else if i < N_PAIRS - N_TWINC {
            Class::TwinCrosspost
        } else {
            Class::TwinCoincidence
        };
        let size = SIZES[i % SIZES.len()];
        let delta = match class {
            Class::Slow => SLOW_DELTAS[i % SLOW_DELTAS.len()],
            _ => FAST_DELTAS[i % FAST_DELTAS.len()],
        };
        let pt = EPOCH + (i as i64) * SPACING;
        let truth = format!("Calib.Subject.{i:03}.2026.1080p.BluRay.x264-CALiB");
        let stem = rng.stem();
        lines.push(pre(&truth, size, pt));
        entries.push((
            "alt.binaries.x264".into(),
            over(&stem, wire(size), pt + delta),
        ));

        match class {
            // A DIFFERENT release, same size, same window: the margin
            // gate's population. A suggestion is fine; a name is not.
            Class::Crowded => lines.push(pre(
                &format!("Other.Subject.{i:03}.2026.1080p.BluRay.x264-RiVAL"),
                size + size / 200,
                pt + 900,
            )),
            // The REPACK shape: same title_key, so a human picks.
            Class::Sibling => lines.push(pre(
                &format!("Calib.Subject.{i:03}.REPACK.2026.1080p.BluRay.x264-CALiB"),
                size + size / 300,
                pt + 600,
            )),
            // Stuff the release's candidate window past CAND_LIMIT with
            // pres at a THIRD of the release's size - far outside
            // [est/RATIO_MAX, est/RATIO_MIN], so the corr_eval size
            // prefilter drops every one before the cap is counted. The
            // pts walk back ~11.4 days from the post, inside its
            // 14-day window and clear of the neighbouring pairs
            // (SPACING is 20 days).
            Class::FloodedWindow => {
                for k in 0..FLOOD_PRES {
                    lines.push(pre(
                        &format!("Calib.Floodrow.{i:03}.K{k:04}.2026.1080p.BluRay.x264-NOISE"),
                        size / 3,
                        pt + delta - 3_600 - (k as i64) * 240,
                    ));
                }
            }
            // Stuff the PRE's forward window past CORR_WINDOW with
            // size-plausible junk releases ([0.90, 1.15]x the true
            // pair's wire bytes, minutes after the pre).
            Class::ForwardCrowded => {
                for k in 0..FWD_DECOYS {
                    let dstem = rng.stem();
                    let w = wire(size) * (90 + (k as u64 % 26)) / 100;
                    entries.push((
                        "alt.binaries.x264".into(),
                        over(&dstem, w, pt + 700 + (k as i64) * 7),
                    ));
                    decoys.push(dstem);
                }
            }
            // The SAME bytes from the SAME poster in a second group,
            // seconds later: a crosspost. One release, two rows.
            Class::TwinCrosspost => {
                entries.push((
                    "alt.binaries.hdtv".into(),
                    over(&stem, wire(size), pt + delta + 30),
                ));
            }
            // A DIFFERENT poster lands near-identical bytes ten minutes
            // later: R2's coincidence population, NOT a repost.
            Class::TwinCoincidence => {
                let dstem = rng.stem();
                entries.push((
                    "alt.binaries.x264".into(),
                    over_as(
                        &dstem,
                        "rival@calib",
                        wire(size) + wire(size) / 250,
                        pt + delta + 600,
                    ),
                ));
                decoys.push(dstem);
            }
            _ => {}
        }

        // A weak background pre in EVERY window: sizeless, sectionless,
        // six days early, so it scores 3 and can never rank - it is
        // here to be a RUNNER-UP.
        //
        // Without it the auto tier's margin clause was vacuous over
        // this whole corpus, and nobody could see that from the
        // numbers. SPACING (20 d) exceeds DELTA_MAX (14 d) by design,
        // so a pair's window held exactly one candidate, and until
        // 2 Sep 2026 `best - runner_up.unwrap_or(0)` read an ABSENT
        // rival as a rival scoring zero: the margin degenerated to the
        // raw score, which had already cleared STRONG to get this far.
        // All 76 auto-applies this harness measured - the ones its
        // 1.0 precision floor is computed over - passed a clause that
        // could not fail. `predb_corr::margin_clears` refuses the empty
        // field now, and this row is what makes the clause do work.
        // The floors below are unchanged: recall stays 1.0 because the
        // filler loses by 81 points.
        lines.push(PreLine {
            kind: PreKind::New,
            title: format!("Calib.Filler.{i:03}"),
            category: String::new(),
            size: 0,
            date: pt - 6 * 86_400,
            source: "CALIB".into(),
            ..Default::default()
        });

        // A music pre of the same size in every fourth window: the kind
        // veto's population. It must never rank anywhere.
        if i % 4 == 0 {
            lines.push(PreLine {
                kind: PreKind::New,
                title: format!("Calib Band {i:03}-Some Album-WEB-2026-CALiB"),
                category: "MP3-WEB".into(),
                size,
                date: pt + 300,
                source: "CALIB".into(),
                ..Default::default()
            });
        }

        pairs.push(Pair { truth, stem, class });
    }

    let now = EPOCH + (N_PAIRS as i64 + 2) * SPACING;
    ix.predb_store(&lines, now).unwrap();
    for (grp, e) in &entries {
        ix.ingest(grp, std::slice::from_ref(e), now).unwrap();
    }

    // The walk itself, auto on, one stride (the corpus is far inside
    // STRIDE) and a budget above the row count. The decoy releases are
    // walked too - they are junk-scored, unnamed rows like any other.
    let n_rows = N_PAIRS + N_EXTRA_RELEASES;
    let (examined, _, _) = ix
        .predb_corr_backlog(n_rows as u32 * 2, 0, true, now)
        .unwrap();
    assert_eq!(
        examined, n_rows,
        "every corpus release must be obfuscated (junk>=70) and unnamed - \
         a corpus the walk skips measures nothing"
    );

    let mut applied = std::collections::HashMap::new();
    let mut suggested = std::collections::HashMap::new();
    for r in ix.search("", (n_rows * 4) as u32).unwrap() {
        if !r.pre_title.is_empty() {
            applied.insert(r.stem.clone(), r.pre_title.clone());
        }
        if let Some(h) = ix.pre_hints(&[r.id]).unwrap().first() {
            suggested.insert(r.stem.clone(), (h.1.clone(), h.5.clone()));
        }
    }
    (pairs, decoys, applied, suggested)
}

fn dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("nzbfast-corr-calib-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// The calibration run. One corpus, one walk, every floor asserted from
/// it - building the corpus is the expensive part and splitting this into
/// separate `#[test]`s would pay for it several times over.
#[test]
fn correlation_tiers_hold_their_precision_floors() {
    let d = dir("tiers");
    let mut ix = Index::open(&d.join("index.db")).unwrap();
    let (pairs, decoys, applied, suggested) = run_corpus(&mut ix);

    // --- Tier: auto. Precision is the safety property, and its floor is
    // exactly 1.0: a wrong name is worse than no name, so a single wrong
    // auto-apply is a failure however good the rest of the run looks.
    let auto_wrong: Vec<(String, String, String)> = pairs
        .iter()
        .filter_map(|p| {
            applied
                .get(&p.stem)
                .filter(|name| *name != &p.truth)
                .map(|name| (p.stem.clone(), p.truth.clone(), name.clone()))
        })
        .collect();
    assert!(
        auto_wrong.is_empty(),
        "auto-tier precision floor is 1.0 - wrong names applied: {auto_wrong:?}"
    );
    // Decoy rows have no truth AT ALL - a coincidence twin or a
    // forward-window filler wearing any applied name is the exact shape
    // a loose twin key or a saturation-blind gate would produce.
    let decoy_named: Vec<(String, String)> = decoys
        .iter()
        .filter_map(|s| applied.get(s).map(|n| (s.clone(), n.clone())))
        .collect();
    assert!(
        decoy_named.is_empty(),
        "decoy releases must never be auto-named: {decoy_named:?}"
    );

    // --- Tier: auto, recall over the population auto is EXPECTED to
    // name: clean-fast pairs, plus the flooded-window pairs whose
    // saturation is false (10 Aug 2026: the corr_eval size prefilter is
    // what lifts it - reverting the prefilter fails this floor, which
    // is the point of the FloodedWindow class). Floor stays 0.95: the
    // population widened by 4 rows that behave exactly like clean-fast
    // once the noise is filtered, so the measured value stays 1.0.
    let expect_auto = |c: Class| matches!(c, Class::CleanFast | Class::FloodedWindow);
    let clean = pairs.iter().filter(|p| expect_auto(p.class)).count();
    let clean_named = pairs
        .iter()
        .filter(|p| expect_auto(p.class) && applied.contains_key(&p.stem))
        .count();
    let recall = clean_named as f64 / clean as f64;
    assert!(
        recall >= 0.95,
        "auto recall over clean-fast + flooded-window pairs fell to {recall:.3} \
         ({clean_named}/{clean}); floor is 0.95"
    );

    // --- The gates, corpus-wide. Each of these has a unit test of its
    // own; asserted here because a population is where a gate that
    // stopped firing shows up as a silent precision loss. ForwardCrowded
    // pins mutual-best's fail-closed saturation; TwinCrosspost pins
    // "a byte-exact same-poster twin self-vetoes the margin" (flipping
    // it to auto is what a tight twin collapse would legitimately do -
    // move the expectation and the floors in that commit, with why);
    // TwinCoincidence pins that a different-poster near-twin keeps
    // suppressing auto on the true pair.
    for p in &pairs {
        if !expect_auto(p.class) {
            assert!(
                !applied.contains_key(&p.stem),
                "{:?} pair {} must never auto-apply (got {:?})",
                p.class,
                p.truth,
                applied.get(&p.stem)
            );
        }
    }

    // --- Tier: suggest. Every pair should carry a suggestion.
    let have = pairs
        .iter()
        .filter(|p| suggested.contains_key(&p.stem))
        .count();
    let coverage = have as f64 / pairs.len() as f64;
    assert!(
        coverage >= 0.95,
        "suggestion coverage fell to {coverage:.3} ({have}/{}); floor is 0.95",
        pairs.len()
    );

    // Top-1 precision, measured only where a top-1 answer is meaningful.
    // The crowded and sibling windows hold a decoy that is, on the
    // evidence correlation is allowed to use, indistinguishable from the
    // truth - ranking it first is not a precision failure, it is why the
    // margin and sibling gates exist, and they are asserted above.
    // Scoring those windows here would bake today's tie-break into a
    // floor and punish a future change for breaking a tie differently.
    let uncontested: Vec<&Pair> = pairs
        .iter()
        .filter(|p| {
            matches!(
                p.class,
                Class::CleanFast | Class::Slow | Class::FloodedWindow
            )
        })
        .collect();
    let top1_right = uncontested
        .iter()
        .filter(|p| suggested.get(&p.stem).is_some_and(|(n, _)| n == &p.truth))
        .count();
    let top1 = top1_right as f64 / uncontested.len() as f64;
    assert!(
        top1 >= 0.98,
        "suggest-tier top-1 precision over uncontested windows fell to {top1:.3} \
         ({top1_right}/{}); floor is 0.98",
        uncontested.len()
    );

    // --- The kind veto, corpus-wide: a music pre must never be the
    // ranked answer for a post in a video group, at any tier.
    for (stem, (name, _)) in &suggested {
        assert!(
            !name.starts_with("Calib Band"),
            "a music pre ranked for video post {stem}: the kind veto is not firing"
        );
    }

    // The record, for `--nocapture`: what the corpus measured, next to
    // what it is allowed to fall to.
    println!(
        "corr calibration over {} pairs: auto precision 1.000 (floor 1.000), \
         auto recall {recall:.3} (floor 0.950), suggestion coverage {coverage:.3} \
         (floor 0.950), uncontested top-1 {top1:.3} (floor 0.980)",
        pairs.len()
    );

    drop(ix);
    std::fs::remove_dir_all(&d).unwrap();
}
