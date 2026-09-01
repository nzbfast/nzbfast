//! TODO 315 / §129: the pool's report that an article's TERMINAL verdict
//! is being HELD BACK, and the one thing that makes it worth having -
//! that it does NOT fire for an article a later backbone answers.
//!
//! The defect it exists for is written up in
//! `research/CHASE-TRIM-DROPS-BEFORE-VERDICT-2026-08-30.md`. The
//! extractor's drop-behind trim vetoes its DROP arm on
//! `Inner::lost_articles`, a flag set from a terminal fetch verdict -
//! and those land late by construction ("retries exhaust last"). Both
//! of this pool's holds sit inside that window: §129's confirming
//! repeat for a bare refusal, and TODO 315's late re-ask. Measured
//! 30 Aug 2026 on the row-26 e2e leg, the trim won that race in 10 of
//! 12 loaded runs, dropped five megabytes of a PAR2-vouched prefix, and
//! every one of the 10 then took the disk ladder because
//! `try_mapped_repair` had no backing data left.
//!
//! [`nzbkit::extract::LossDoubt`] is that veto raised one round trip
//! earlier, and the reason it is a SEPARATE flag rather than an earlier
//! `lost_articles` is that it must not arm the stalled-chase paging
//! pass, which does real disk I/O and wants the terminal mark.
//!
//! EACH HOLD GETS A LEG THAT ONLY IT CAN SATISFY, and that is not
//! ceremony. On a fleet with one echoing and one bare backbone BOTH
//! holds fire for the same article, so a single "it was raised" leg
//! stays green with either raise site deleted - an arm no case can kill
//! is an arm nothing is testing. Making every backbone echo is exactly
//! the condition §129's repeat is skipped under, so that leg can only be
//! TODO 315's; turning TODO 315 off at the config leaves §129's repeat
//! as the only hold in the run.
//!
//! THE LAST LEG IS THE ONE THAT COSTS SOMETHING TO GET WRONG. The flag
//! is per-JOB and sticky, so raising it on an ordinary ladder refusal -
//! one backbone of several that does not hold an article the next one
//! does - would stand the drop down for whole CLEAN downloads and give
//! back the 0.48x of spilled disk the drop exists to avoid (measured
//! 21 Aug 2026, `research/MEASURED-HOLDS-LADDER-2026-08-21.md`). That
//! is why the raise is gated on the refusal completing the LIVE mask,
//! and why that leg asserts the refusal really happened rather than
//! passing because nothing was ever asked.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use nzbkit::config::ServerConfig;
use nzbkit::extract::LossDoubt;
use nzbkit::mock::{Chaos, MockServer, make_file_articles};
use nzbkit::pool::{ArticleReq, FetchOutcome, LiveStats, PoolConfig, fetch_all_multi};
use tokio::sync::mpsc;

/// Payload bytes per article. Small: nothing here measures throughput.
const ART: usize = 4_000;

/// What one leg reports.
struct Leg {
    doubt: bool,
    missing: usize,
    done: usize,
    /// Wire refusals, summed over the fleet - the teeth on the
    /// `answered` leg, which would otherwise pass on a run where the
    /// article never reached the refusing server at all.
    refusals: u64,
}

/// How a leg is shaped.
struct Shape {
    /// Both backbones refuse the victim, so it really is unanswerable.
    everywhere: bool,
    /// Whether each backbone echoes the id on its refusal line, which
    /// is what decides whether §129's confirming repeat is spent there
    /// at all. Both echoing leaves TODO 315's late re-ask as the only
    /// hold in the run; the FIRST one bare is the only way to reach a
    /// bare refusal that is NOT the article's last evidence, which is
    /// the case the unanimity guard exists for.
    echo: [bool; 2],
    /// `PoolConfig::recheck_430`. Off leaves §129's repeat as the only
    /// hold left.
    recheck: bool,
}

/// Two backbones against four healthy articles plus one victim.
///
/// The tiers are M14e's and they are what makes the ordering
/// DETERMINISTIC rather than a coin flip: a level-1 server only takes
/// queued work every live level-0 server has already 430'd, so the
/// victim reaches the backbone that holds it only AFTER the one that
/// refuses it has said so. Without that the two race for the item, the
/// refusing one is skipped about half the time, and a leg that never
/// asked it asserts nothing while still passing.
async fn leg(shape: Shape) -> Leg {
    let data: Vec<u8> = (0..(ART * 4) as u32).map(|i| i as u8).collect();
    let mut articles: HashMap<String, Vec<u8>> = HashMap::new();
    let segs = make_file_articles("payload.bin", &data, ART, "good", &mut articles);
    // A REAL article on the server that holds it, so the `answered` leg
    // ends with a body and not with a second verdict - built through the
    // same helper, because a hand-rolled body is not a yEnc part.
    let vseg = make_file_articles("victim.bin", &vec![7u8; ART], ART, "victim", &mut articles);
    let victim = format!("<{}>", vseg[0].0);

    let mut mocks = Vec::new();
    for si in 0..2usize {
        let chaos = Chaos {
            missing: if shape.everywhere || si == 0 {
                [victim.clone()].into_iter().collect::<HashSet<String>>()
            } else {
                HashSet::new()
            },
            echo_missing_id: shape.echo[si],
            ..Default::default()
        };
        mocks.push(MockServer::start(articles.clone(), chaos).await);
    }

    let doubt = Arc::new(LossDoubt::default());
    let servers: Vec<(ServerConfig, PoolConfig)> = mocks
        .iter()
        .enumerate()
        .map(|(si, m)| {
            let mut sc = m.server_config();
            sc.connections = 2;
            sc.level = si as u32;
            (
                sc,
                PoolConfig {
                    connections: 2,
                    ramp_delay: Duration::from_millis(0),
                    recheck_430: shape.recheck,
                    loss_doubt: Some(doubt.clone()),
                    ..Default::default()
                },
            )
        })
        .collect();
    let live = LiveStats::for_servers(&servers);
    let servers: Vec<(ServerConfig, PoolConfig)> = servers
        .into_iter()
        .map(|(s, mut c)| {
            c.live = Some(live.clone());
            (s, c)
        })
        .collect();

    let mut reqs: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    reqs.push(ArticleReq::fresh(victim));

    let (tx, mut rx) = mpsc::channel(64);
    let fetch = tokio::spawn(async move { fetch_all_multi(&servers, reqs, tx).await });
    let (mut done, mut missing) = (0usize, 0usize);
    while let Some(o) = rx.recv().await {
        match o {
            FetchOutcome::Done { .. } => done += 1,
            FetchOutcome::Missing { .. } => missing += 1,
            FetchOutcome::Failed { .. } => {}
        }
    }
    fetch.await.unwrap();
    let refusals = live
        .servers
        .iter()
        .map(|s| s.articles_missing.load(Ordering::Relaxed))
        .sum();
    Leg {
        doubt: doubt.raised(),
        missing,
        done,
        refusals,
    }
}

/// TODO 315's late re-ask raises the doubt: every backbone echoes, so
/// §129's confirming repeat is never spent and this hold is the only
/// one in the run.
#[tokio::test(flavor = "multi_thread")]
async fn the_late_re_ask_hold_raises_the_doubt() {
    let leg = leg(Shape {
        everywhere: true,
        echo: [true, true],
        recheck: true,
    })
    .await;
    assert_eq!(leg.done, 4, "the healthy articles must still arrive");
    assert_eq!(leg.missing, 1, "the victim must still go terminal");
    assert!(
        leg.doubt,
        "TODO 315 held a terminal verdict back and said nothing - the \
         drop-behind trim is racing that verdict again"
    );
}

/// And §129's confirming repeat raises it too, with TODO 315 turned off
/// at the config so the re-ask cannot be what did it.
#[tokio::test(flavor = "multi_thread")]
async fn the_bare_refusal_repeat_raises_the_doubt() {
    let leg = leg(Shape {
        everywhere: true,
        echo: [true, false],
        recheck: false,
    })
    .await;
    assert_eq!(leg.done, 4, "the healthy articles must still arrive");
    assert_eq!(leg.missing, 1, "the victim must still go terminal");
    assert!(
        leg.doubt,
        "a bare last-evidence refusal was requeued for its confirming \
         repeat and said nothing - the window §129 opens is unguarded"
    );
}

/// An article the SECOND backbone holds raises nothing, however loudly
/// the first one refuses it. This is the precision the raise is gated
/// for: the flag is per-job and sticky, so firing here would stand the
/// drop down for every clean multi-provider download.
#[tokio::test(flavor = "multi_thread")]
async fn an_article_the_next_backbone_answers_raises_nothing() {
    let leg = leg(Shape {
        everywhere: false,
        // BARE, and that is the point of this leg: an ECHOED refusal
        // that is not last evidence never reaches `note_doubt` at all,
        // so only a bare one can exercise the unanimity guard - and
        // this one is a single backbone's refusal of an article the
        // tier above it holds.
        echo: [false, true],
        recheck: true,
    })
    .await;
    assert_eq!(leg.done, 5, "every article, the victim included, arrives");
    assert_eq!(leg.missing, 0, "nothing may go terminal here");
    // Teeth: without a refusal on the wire this leg asserts nothing.
    assert!(
        leg.refusals >= 1,
        "the refusing backbone was never asked - the leg proves nothing"
    );
    assert!(
        !leg.doubt,
        "an ordinary ladder refusal raised the job-wide doubt: every \
         clean download on a fleet whose first server lacks an article \
         would stop dropping and pay the spill back"
    );
}
