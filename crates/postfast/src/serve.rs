//! `[serve]`, the serve-time half of plane 7.F: what the mock server
//! does to its ANSWERS, as opposed to what the generator baked into the
//! bytes.
//!
//! **Nothing here implements a fault.** Every shape this module can
//! select is a field of `nzbkit::mock::Chaos`, which is the one fault
//! server in this repo and the one the whole e2e suite already drives.
//! This module's entire job is to turn "2 % of the articles" into the
//! set of message-ids that 2 % names, reproducibly, and to put that set
//! in the Chaos field the profile spelled. A fault Chaos cannot express
//! is a KNOB IN `nzbkit::mock` with a test of its own, never a parallel
//! mechanism here: a second fault server would be a second thing to
//! keep faithful to real providers, and the first one carries about
//! forty knobs and years of measured shapes behind them.
//!
//! **A profile names articles two ways and both are reproducible.** A
//! percentage is drawn from the seed; a position list names articles
//! outright. Positions are 0-BASED indices into the post's articles in
//! POSTING ORDER - payload files in `[source]` order, then the recovery
//! files, each file's segments in segment order - which is the order
//! `crate::encode` returns and the order an author reading the NZB
//! sees. A position past the end is refused by name rather than
//! ignored: a fault plan that damaged nothing would leave the row
//! green over the clean layout it was written to replace.
//!
//! **One article, one fault.** The named positions are removed from the
//! pool first, then the percentages are drawn from what is left, so a
//! plan asking for 2 % missing and 2 % corrupt damages 4 % of the post
//! and never asks the server to do two things to one article (where the
//! mock's own precedence would silently decide which one happened).
//! `swap` is the exception and says so at its own draw.
//!
//! **A percentage that rounds to zero still takes one article.** Over
//! the small posts a catalog profile is asked to keep, 2 % of twelve
//! articles is 0.24, and a fault plan that damages nothing is a row
//! that proves nothing while reading like it proves something. The
//! rounding is up to one, never down to zero, and this is the one place
//! it is written down.
//!
//! **The stream is the fault plane's own**, derived from the profile's
//! seed - see [`crate::fault`]'s header for the reason, which is the
//! same reason: adding `[serve]` to a profile must not move a single
//! payload name or message-id, or a fault row could not be diffed
//! against the clean twin it was written from.

use std::collections::{HashMap, HashSet};

use nzbkit::mock::Chaos;

use crate::encode::EncodedFile;
use crate::profile::{Profile, SecondServer, Serve};
use crate::rng::Rng;

/// The stream label for the serve plane. See [`crate::fault::STREAM`]
/// for what a label is and why the two differ. `pub(crate)` only so a
/// test can assert the two are not one constant.
pub(crate) const STREAM: u64 = 0x5345_5256_4520_2020; // "SERVE   "

/// Why a serve-time fault plan could not be built.
///
/// `PartialEq` and no `Eq`: one arm carries the percentage an author
/// wrote, so the type holds an `f64` and cannot claim total equality.
#[derive(Debug, Clone, PartialEq)]
pub enum ServeError {
    /// A position list names an article the post does not have.
    NoSuchArticle {
        field: &'static str,
        position: u32,
        articles: usize,
    },
    /// One position named twice, in one list or across two. Refused
    /// because "one article, one fault" is what makes a plan gradeable,
    /// and the mock's precedence would otherwise pick silently.
    PositionTwice { position: u32 },
    /// A percentage outside 0..=100.
    Percentage { field: &'static str, given: f64 },
    /// More faults asked for than there are articles to carry them.
    NotEnoughArticles { asked: usize, articles: usize },
    /// `swap` over a post with one article, which has nothing to be
    /// swapped with.
    SwapNeedsTwoArticles,
    /// `slow_ttfb` positions with no delay to serve them behind.
    SlowTtfbWithoutMs,
}

impl std::fmt::Display for ServeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSuchArticle {
                field,
                position,
                articles,
            } => write!(
                f,
                "[serve] {field} names article {position}, and the post carries {articles} \
                 (positions 0..{}). Positions are 0-based over the whole post in posting \
                 order, payload first then the recovery files",
                articles.saturating_sub(1)
            ),
            Self::PositionTwice { position } => write!(
                f,
                "[serve] article {position} is named by two faults. One article carries one \
                 fault here, so that a plan says what happened rather than leaving the \
                 mock's own precedence to decide it"
            ),
            Self::Percentage { field, given } => write!(
                f,
                "[serve] {field} = {given} is not a percentage in 0..=100"
            ),
            Self::NotEnoughArticles { asked, articles } => write!(
                f,
                "[serve] asks for {asked} damaged articles and the post carries {articles}. \
                 Ask for less, or give [source] enough bytes to be split further"
            ),
            Self::SwapNeedsTwoArticles => f.write_str(
                "[serve] swap answers one article's request with ANOTHER article's body, and \
                 this post has only one article to serve",
            ),
            Self::SlowTtfbWithoutMs => f.write_str(
                "[serve] slow_ttfb names articles and slow_ttfb_ms is 0: dead air of zero \
                 length is not a fault, so the plan would read as a fault and be none",
            ),
        }
    }
}

impl std::error::Error for ServeError {}

/// The knobs one server's fault plan carries, as a borrowed view.
///
/// [`Serve`] and [`SecondServer`] repeat the field list because
/// `deny_unknown_fields` and `flatten` cannot both hold in serde, and a
/// typo in a fault plan has to be a load error. That repetition stops
/// here: [`build`] below is written once, against this view, so the two
/// servers cannot drift into meaning different things by the same
/// field name.
struct Knobs<'a> {
    missing: &'a [u32],
    corrupt: &'a [u32],
    missing_pct: f64,
    missing_once_pct: f64,
    corrupt_pct: f64,
    corrupt_once_pct: f64,
    truncate: &'a [u32],
    stall: &'a [u32],
    stall_pre: &'a [u32],
    swap: &'a [u32],
    slow_ttfb: &'a [u32],
    slow_ttfb_ms: u64,
}

impl<'a> From<&'a Serve> for Knobs<'a> {
    fn from(s: &'a Serve) -> Self {
        Self {
            missing: &s.missing,
            corrupt: &s.corrupt,
            missing_pct: s.missing_pct,
            missing_once_pct: s.missing_once_pct,
            corrupt_pct: s.corrupt_pct,
            corrupt_once_pct: s.corrupt_once_pct,
            truncate: &s.truncate,
            stall: &s.stall,
            stall_pre: &s.stall_pre,
            swap: &s.swap,
            slow_ttfb: &s.slow_ttfb,
            slow_ttfb_ms: s.slow_ttfb_ms,
        }
    }
}

impl<'a> From<&'a SecondServer> for Knobs<'a> {
    fn from(s: &'a SecondServer) -> Self {
        Self {
            missing: &s.missing,
            corrupt: &s.corrupt,
            missing_pct: s.missing_pct,
            missing_once_pct: s.missing_once_pct,
            corrupt_pct: s.corrupt_pct,
            corrupt_once_pct: s.corrupt_once_pct,
            truncate: &s.truncate,
            stall: &s.stall,
            stall_pre: &s.stall_pre,
            swap: &s.swap,
            slow_ttfb: &s.slow_ttfb,
            slow_ttfb_ms: s.slow_ttfb_ms,
        }
    }
}

/// Build the `Chaos` for the first server and for every further one the
/// profile asks for.
///
/// Draw order: the first server's plan in field order, then each
/// further server's in list order. Adding a second server therefore
/// leaves the first server's chosen articles exactly where they were,
/// which is what lets an S6 row be diffed against the one-server row it
/// was written from.
pub fn plan(profile: &Profile, encoded: &[EncodedFile]) -> Result<(Chaos, Vec<Chaos>), ServeError> {
    let ids = article_ids(encoded);
    let mut rng = Rng::from_seed(profile.layout.seed ^ STREAM);
    let first = build(&Knobs::from(&profile.serve), &ids, &mut rng)?;
    let mut rest = Vec::with_capacity(profile.serve.second.len());
    for s in &profile.serve.second {
        rest.push(build(&Knobs::from(s), &ids, &mut rng)?);
    }
    Ok((first, rest))
}

/// Every article's message-id, WITH angle brackets, in posting order.
///
/// The brackets are not cosmetic: `Chaos` keys are the id as it appears
/// on the wire, which is the form `Layout::articles` is keyed by and
/// the form the mock matches against. A set built without them matches
/// nothing and the server answers every article correctly, which is a
/// fault plan that reads as one and is not.
fn article_ids(encoded: &[EncodedFile]) -> Vec<String> {
    encoded
        .iter()
        .flat_map(|f| f.segments.iter())
        .map(|s| format!("<{}>", s.message_id))
        .collect()
}

/// Turn one server's knobs into one `Chaos`.
fn build(k: &Knobs<'_>, ids: &[String], rng: &mut Rng) -> Result<Chaos, ServeError> {
    let n = ids.len();
    for (field, pct) in [
        ("missing_pct", k.missing_pct),
        ("missing_once_pct", k.missing_once_pct),
        ("corrupt_pct", k.corrupt_pct),
        ("corrupt_once_pct", k.corrupt_once_pct),
    ] {
        if !(0.0..=100.0).contains(&pct) {
            return Err(ServeError::Percentage { field, given: pct });
        }
    }
    if !k.slow_ttfb.is_empty() && k.slow_ttfb_ms == 0 {
        return Err(ServeError::SlowTtfbWithoutMs);
    }

    // The named positions come out of the pool first, so a percentage
    // can never land on an article the profile already spoke for.
    let mut spoken = HashSet::new();
    let mut named = |field: &'static str, list: &[u32]| -> Result<Vec<usize>, ServeError> {
        let mut out = Vec::with_capacity(list.len());
        for &p in list {
            if p as usize >= n {
                return Err(ServeError::NoSuchArticle {
                    field,
                    position: p,
                    articles: n,
                });
            }
            if !spoken.insert(p) {
                return Err(ServeError::PositionTwice { position: p });
            }
            out.push(p as usize);
        }
        Ok(out)
    };
    let missing_at = named("missing", k.missing)?;
    let corrupt_at = named("corrupt", k.corrupt)?;
    let truncate = named("truncate", k.truncate)?;
    let stall = named("stall", k.stall)?;
    let stall_pre = named("stall_pre", k.stall_pre)?;
    let slow = named("slow_ttfb", k.slow_ttfb)?;
    // `swap` is the exception to "one article, one fault", and
    // deliberately: a swapped article is served WHOLE and correct, just
    // the wrong one, so it is not damage the other faults could collide
    // with - it is a different article arriving. It still may not be
    // named twice, which the shared `spoken` set enforces.
    let swap_at = named("swap", k.swap)?;

    // What is left, in posting order, is what a percentage may draw
    // from. Shuffled once and consumed from the front, so two
    // percentages in one plan cannot pick the same article and the
    // whole plan is one pass over one permutation.
    let mut pool: Vec<usize> = (0..n).filter(|i| !spoken.contains(&(*i as u32))).collect();
    for i in (1..pool.len()).rev() {
        let j = rng.below(i as u64 + 1) as usize;
        pool.swap(i, j);
    }
    let mut taken = 0usize;
    let mut take = |pct: f64| -> Result<HashSet<String>, ServeError> {
        let want = count_for(pct, n);
        if taken + want > pool.len() {
            return Err(ServeError::NotEnoughArticles {
                asked: taken + want,
                articles: n,
            });
        }
        let set = pool[taken..taken + want]
            .iter()
            .map(|&i| ids[i].clone())
            .collect();
        taken += want;
        Ok(set)
    };
    // The named positions join the drawn sets: one field, two ways of
    // filling it, and the mock never learns which half an id came from.
    let mut missing = take(k.missing_pct)?;
    missing.extend(missing_at.into_iter().map(|i| ids[i].clone()));
    let missing_once = take(k.missing_once_pct)?;
    let mut corrupt = take(k.corrupt_pct)?;
    corrupt.extend(corrupt_at.into_iter().map(|i| ids[i].clone()));
    let corrupt_once = take(k.corrupt_once_pct)?;

    // The swap partner is drawn AFTER the pool, from the whole post: a
    // partner is served as itself everywhere else, so it is not a fault
    // and does not consume the pool. Drawn from `n - 1` and stepped
    // past the article itself, so it is never its own partner (which
    // the mock would serve correctly, making the row a no-op).
    let mut swap = HashMap::with_capacity(swap_at.len());
    for at in swap_at {
        if n < 2 {
            return Err(ServeError::SwapNeedsTwoArticles);
        }
        let mut other = rng.below(n as u64 - 1) as usize;
        if other >= at {
            other += 1;
        }
        swap.insert(ids[at].clone(), ids[other].clone());
    }

    Ok(Chaos {
        missing,
        missing_once,
        corrupt,
        corrupt_once,
        truncate: truncate.into_iter().map(|i| ids[i].clone()).collect(),
        stall: stall.into_iter().map(|i| ids[i].clone()).collect(),
        stall_pre: stall_pre.into_iter().map(|i| ids[i].clone()).collect(),
        swap,
        slow_ttfb: slow
            .into_iter()
            .map(|i| (ids[i].clone(), k.slow_ttfb_ms))
            .collect(),
        ..Chaos::default()
    })
}

/// How many articles a percentage names.
///
/// Rounded to nearest, then floored at ONE whenever the percentage is
/// above zero and there is an article to take: see this module's
/// header. A catalog profile is asked to keep its payload small, so
/// almost every percentage a row wants to write rounds to zero on
/// arithmetic alone, and a fault plan that damages nothing is the
/// rubber stamp the whole generator refuses planes to prevent.
fn count_for(pct: f64, n: usize) -> usize {
    if pct <= 0.0 || n == 0 {
        return 0;
    }
    let exact = n as f64 * pct / 100.0;
    (exact.round() as usize).clamp(1, n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::generate;

    /// Twelve articles over one file, so a percentage's rounding and a
    /// position's index are both easy to reason about by hand.
    const BASE: &str = "\
[layout]
name = \"t\"
seed = 3

[source]
files = [{ name = \"payload.bin\", bytes = 240000 }]

[encoding]
article_bytes = 20000
";

    fn built(extra: &str) -> crate::Layout {
        let p = Profile::parse(&format!("{BASE}{extra}")).expect("profile parses");
        generate(&p).expect("layout generates")
    }

    fn refused(extra: &str) -> ServeError {
        let p = Profile::parse(&format!("{BASE}{extra}")).expect("profile parses");
        match generate(&p) {
            Err(crate::layout::GenError::Serve(e)) => e,
            other => panic!("expected a serve refusal, got {other:?}"),
        }
    }

    /// THE ACCEPTANCE PROPERTY: one seed, one missing set, whoever
    /// generates it and however often.
    #[test]
    fn one_seed_picks_the_same_missing_set_twice() {
        let extra = "\n[serve]\nmissing_pct = 25.0\n";
        let a = built(extra);
        let b = built(extra);
        let mut left: Vec<&String> = a.chaos.missing.iter().collect();
        let mut right: Vec<&String> = b.chaos.missing.iter().collect();
        left.sort();
        right.sort();
        assert_eq!(left, right);
        assert_eq!(a.chaos.missing.len(), 3, "25 % of twelve articles");
    }

    /// ...and the seed is what makes it so, or a generator that always
    /// picked the first three articles would pass the test above.
    #[test]
    fn a_different_seed_picks_a_different_missing_set() {
        let extra = "\n[serve]\nmissing_pct = 25.0\n";
        let a = built(extra);
        let p = Profile::parse(&format!("{}{extra}", BASE.replace("seed = 3", "seed = 4")))
            .expect("profile parses");
        let b = generate(&p).expect("layout generates");
        assert_ne!(a.chaos.missing, b.chaos.missing);
    }

    /// A percentage too small to round to a whole article still damages
    /// one. See this module's header: over the small posts a catalog row
    /// is asked to keep, rounding down would leave a fault plan that
    /// reads as a fault and is none.
    #[test]
    fn a_percentage_that_rounds_to_zero_still_takes_one_article() {
        let l = built("\n[serve]\nmissing_pct = 2.0\n");
        assert_eq!(l.chaos.missing.len(), 1);
    }

    /// Zero is zero, though - the floor is for a percentage an author
    /// wrote, not for an absent table.
    #[test]
    fn a_neutral_plan_damages_nothing() {
        let l = built("");
        assert!(l.chaos.missing.is_empty());
        assert!(l.chaos.corrupt.is_empty());
        assert!(l.chaos.swap.is_empty());
        assert!(l.second.is_empty());
    }

    /// Every id a plan hands the server is an id the layout actually
    /// serves, angle brackets and all. A set built without them matches
    /// nothing and the server answers correctly, which is a fault plan
    /// that reads as one and is not.
    #[test]
    fn every_chosen_id_is_an_article_the_layout_serves() {
        let l = built(
            "\n[serve]\nmissing_pct = 10.0\ncorrupt_pct = 10.0\ntruncate = [0]\nstall = [1]\n\
             stall_pre = [2]\nswap = [3]\nslow_ttfb = [4]\nslow_ttfb_ms = 5\n",
        );
        let chosen = l
            .chaos
            .missing
            .iter()
            .chain(&l.chaos.corrupt)
            .chain(&l.chaos.truncate)
            .chain(&l.chaos.stall)
            .chain(&l.chaos.stall_pre)
            .chain(l.chaos.swap.keys())
            .chain(l.chaos.swap.values())
            .chain(l.chaos.slow_ttfb.keys());
        for id in chosen {
            assert!(
                l.articles.contains_key(id),
                "{id} is not an article this layout serves"
            );
        }
    }

    /// One article, one fault: a named position is taken out of the
    /// pool before a percentage draws from it.
    #[test]
    fn a_named_position_is_never_also_drawn() {
        let l = built("\n[serve]\ntruncate = [0, 1, 2, 3, 4, 5]\nmissing_pct = 50.0\n");
        assert_eq!(l.chaos.truncate.len(), 6);
        assert_eq!(l.chaos.missing.len(), 6);
        for id in &l.chaos.missing {
            assert!(!l.chaos.truncate.contains(id), "{id} carries two faults");
        }
    }

    /// The named and drawn halves of one field land in the same set: the
    /// mock never learns which half an id came from.
    #[test]
    fn a_named_position_and_a_percentage_fill_one_field() {
        let l = built("\n[serve]\nmissing = [0]\nmissing_pct = 25.0\n");
        assert_eq!(l.chaos.missing.len(), 4, "three drawn plus one named");
    }

    /// A swap partner is another article, never the swapped one, which
    /// the mock would serve correctly.
    #[test]
    fn a_swap_partner_is_a_different_article() {
        let l = built("\n[serve]\nswap = [0, 5, 11]\n");
        assert_eq!(l.chaos.swap.len(), 3);
        for (k, v) in &l.chaos.swap {
            assert_ne!(k, v, "an article swapped with itself is not a fault");
        }
    }

    /// Adding a second server leaves the first server's plan exactly
    /// where it was, so an S6 row diffs against the row it was written
    /// from.
    #[test]
    fn a_second_server_does_not_move_the_first_servers_plan() {
        let one = built("\n[serve]\nmissing_pct = 25.0\n");
        let two = built("\n[serve]\nmissing_pct = 25.0\n\n[[serve.second]]\nmissing_pct = 100.0\n");
        assert_eq!(one.chaos.missing, two.chaos.missing);
        assert_eq!(two.second.len(), 1);
        assert_eq!(
            two.second[0].missing.len(),
            two.articles.len(),
            "100 % is every article"
        );
    }

    /// Two second servers, in the order the profile writes them.
    #[test]
    fn every_further_server_gets_its_own_plan() {
        let l = built(
            "\n[[serve.second]]\nmissing_pct = 100.0\n\n[[serve.second]]\nmissing_pct = 25.0\n",
        );
        assert_eq!(l.second.len(), 2);
        assert_eq!(l.second[0].missing.len(), l.articles.len());
        assert_eq!(l.second[1].missing.len(), 3);
    }

    /// Adding `[serve]` moves nothing else about the layout. The plane
    /// draws from its own stream precisely so a fault row can be diffed
    /// against the clean row it was copied from.
    #[test]
    fn adding_a_serve_plan_moves_no_name_and_no_message_id() {
        let clean = built("");
        let faulty = built("\n[serve]\nmissing_pct = 25.0\nswap = [0]\n");
        assert_eq!(clean.files, faulty.files);
        assert_eq!(clean.articles, faulty.articles);
        assert_eq!(clean.nzb, faulty.nzb);
        assert_eq!(clean.expect.files, faulty.expect.files);
    }

    /// Failing to find is failing: a position the post does not have is
    /// refused, with the range, rather than quietly damaging nothing.
    #[test]
    fn a_position_past_the_end_is_refused_with_the_range() {
        let e = refused("\n[serve]\ntruncate = [12]\n");
        assert_eq!(
            e,
            ServeError::NoSuchArticle {
                field: "truncate",
                position: 12,
                articles: 12
            }
        );
        assert!(e.to_string().contains("0..11"), "{e}");
    }

    /// One position, one fault - across two fields as well as within
    /// one, because the mock's own precedence would otherwise decide
    /// which of the two happened.
    #[test]
    fn a_position_named_twice_is_refused() {
        for extra in [
            "\n[serve]\ntruncate = [3, 3]\n",
            "\n[serve]\ntruncate = [3]\nstall = [3]\n",
        ] {
            assert_eq!(refused(extra), ServeError::PositionTwice { position: 3 });
        }
    }

    /// A percentage is a percentage.
    #[test]
    fn a_percentage_outside_the_range_is_refused_by_field() {
        let e = refused("\n[serve]\ncorrupt_pct = 140.0\n");
        assert!(matches!(
            e,
            ServeError::Percentage {
                field: "corrupt_pct",
                ..
            }
        ));
        assert!(
            refused("\n[serve]\nmissing_pct = -1.0\n")
                .to_string()
                .contains("missing_pct")
        );
    }

    /// More faults than there are articles to carry them.
    #[test]
    fn a_plan_bigger_than_the_post_is_refused() {
        let e = refused("\n[serve]\nmissing_pct = 60.0\ncorrupt_pct = 60.0\n");
        assert!(matches!(e, ServeError::NotEnoughArticles { .. }), "{e}");
    }

    /// Dead air of zero length is not a fault, so a plan that reads as
    /// one and is none is refused rather than served.
    #[test]
    fn slow_ttfb_without_a_delay_is_refused() {
        assert_eq!(
            refused("\n[serve]\nslow_ttfb = [0]\n"),
            ServeError::SlowTtfbWithoutMs
        );
    }

    /// The delay reaches the server, per article.
    #[test]
    fn the_slow_ttfb_delay_is_carried_per_article() {
        let l = built("\n[serve]\nslow_ttfb = [0, 1]\nslow_ttfb_ms = 250\n");
        assert_eq!(l.chaos.slow_ttfb.len(), 2);
        assert!(l.chaos.slow_ttfb.values().all(|&ms| ms == 250));
    }

    /// The rounding rule, at its edges, without going through a layout.
    #[test]
    fn count_for_rounds_to_nearest_and_floors_at_one() {
        assert_eq!(count_for(0.0, 12), 0);
        assert_eq!(count_for(0.1, 12), 1, "never down to zero");
        assert_eq!(count_for(25.0, 12), 3);
        assert_eq!(count_for(100.0, 12), 12);
        assert_eq!(count_for(50.0, 0), 0, "no articles, no faults");
    }
}
