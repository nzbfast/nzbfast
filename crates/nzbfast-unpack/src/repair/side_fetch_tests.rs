//! Side-fetch cancellation tests (Codex 5 Aug M3). A child module of
//! `repair` so repair.rs keeps its size-gate baseline - same pattern
//! as pool/unit_tests.rs.

use super::*;

fn tdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("nzbfast-sidefetch-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// The 7 Aug 2026 daemon wedge: the post-download repair fetch handed
/// `fetch_volume_articles` the MAIN fleet's pool configs, and on a
/// multi-server setup those carry `crc_steer: true` - a seam that parks
/// every delivered body's completion until a `note_decoded` verdict the
/// side-fetch consumer never gives (it has no QueueControl). The
/// articles all landed (the volume was fully on disk) but the pool
/// never drained, so the job sat in "Repairing" forever with the whole
/// finalize chain wedged behind it. The driver must strip the consumer
/// ack seams itself: a steer-mode config must complete, deliver the
/// volume, and hand control back so an unrepairable job can FAIL
/// instead of hanging the daemon.
#[tokio::test]
async fn a_steer_config_side_fetch_still_completes() {
    use nzbkit::mock::{Chaos, MockServer};
    use nzbkit::pool::ArticleReq;
    let payload = b"not really par2, but the bytes prove delivery";
    let body = nzbkit::yenc::encode(
        "wedge.vol002+004.par2",
        payload.len() as u64,
        Some((1, 1)),
        1,
        payload,
    );
    let mut arts = std::collections::HashMap::new();
    arts.insert("<vol@wedge>".to_string(), body);
    let srv = MockServer::start(arts, Chaos::default()).await;
    // The main fleet's shape, NOT side_pool_servers: both consumer-ack
    // seams on, exactly what run_set_repair passes through.
    let pc = nzbkit::pool::PoolConfig {
        crc_steer: true,
        arrival_ack: true,
        ..Default::default()
    };
    let servers = vec![(srv.server_config(), pc)];
    let dir = tdir("steer-complete");
    let mut idm = std::collections::HashMap::new();
    idm.insert(std::sync::Arc::<str>::from("<vol@wedge>"), 0usize);
    let ids = vec![ArticleReq {
        id: "<vol@wedge>".into(),
        age_days: 0,
        part: 1,
        file: u32::MAX,
    }];
    let (failures, paths) = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        fetch_volume_articles(
            &servers,
            ids,
            idm,
            &dir,
            &nzbkit::pool::BufPool::new(4),
            u64::MAX,
            None,
        ),
    )
    .await
    .expect("a side-fetch under steer-mode configs must drain and return, not park forever")
    .expect("harvest succeeds");
    assert_eq!(
        failures.total(),
        0,
        "the one article was served and decoded"
    );
    assert_eq!(paths.len(), 1, "the volume file was assembled");
    let written = std::fs::read(&paths[0]).unwrap();
    assert_eq!(written, payload, "delivered bytes reached the disk");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Codex 5 Aug M3: a side-fetch against a blackholed provider used to
/// run its whole multi-session retry ladder with no way to stop it,
/// holding drain_network's await - and with it Cancel/Pause - for
/// minutes. A `SideCancel` must bring `fetch_volume_articles` home
/// promptly.
///
/// ONE `cancel()`, deliberately: the caller no longer keeps re-aborting
/// (the prefetch used to, in its own watcher). The re-abort now lives
/// inside the driver, because `QueueControl::abort` only reaches the
/// pool attached at that instant and the pool attaches inside this
/// call - so a single cancel racing the attach is exactly the case that
/// must still work.
#[tokio::test]
async fn a_cancelled_side_fetch_returns_promptly() {
    use nzbkit::mock::{Chaos, MockServer};
    use nzbkit::pool::ArticleReq;
    // A provider that accepts the TCP connect and never greets - the
    // blackhole shape that held the ladder hostage.
    let chaos = Chaos {
        mute_greeting: true,
        ..Default::default()
    };
    let srv = MockServer::start(std::collections::HashMap::new(), chaos).await;
    let servers = side_pool_servers(&[(srv.server_config(), nzbkit::pool::PoolConfig::default())]);
    let dir = tdir("m3-abort");
    let cancel = Arc::new(SideCancel::new());
    let canceller = {
        let cancel = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            cancel.cancel();
        })
    };
    let mut idm = std::collections::HashMap::new();
    idm.insert(std::sync::Arc::<str>::from("<vol@x>"), 0usize);
    let ids = vec![ArticleReq {
        id: "<vol@x>".into(),
        age_days: 0,
        part: 1,
        file: u32::MAX,
    }];
    let t0 = std::time::Instant::now();
    let res = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        fetch_volume_articles(
            &servers,
            ids,
            idm,
            &dir,
            &nzbkit::pool::BufPool::new(4),
            u64::MAX,
            Some(&cancel),
        ),
    )
    .await
    .expect("a cancelled side-fetch must not run the full retry ladder");
    let _ = canceller.await;
    // Well under the ladder's multi-session budget (each connect
    // alone is allowed 20 s); generous against a loaded CI box.
    assert!(
        t0.elapsed() < std::time::Duration::from_secs(15),
        "cancel took {:?}",
        t0.elapsed()
    );
    // Err, not a clean harvest: an aborted run's unresolved articles
    // emit no outcome, so a zero failure count over a short volume
    // would be a lie a caller is entitled to act on.
    let e = res.expect_err("a cancelled fetch reports cancelled");
    assert!(
        e.to_string().contains("cancelled"),
        "verdict should name the cancel, got {e}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A handle cancelled BEFORE the call never touches the network at all.
/// The lane's repair walks a ladder of volumes; once the job is gone,
/// every remaining rung must be a no-op rather than a fetch whose bytes
/// are discarded on arrival.
#[tokio::test]
async fn a_pre_cancelled_side_fetch_never_dials() {
    use nzbkit::mock::{Chaos, MockServer};
    use nzbkit::pool::ArticleReq;
    let chaos = Chaos {
        mute_greeting: true,
        ..Default::default()
    };
    let srv = MockServer::start(std::collections::HashMap::new(), chaos).await;
    let servers = side_pool_servers(&[(srv.server_config(), nzbkit::pool::PoolConfig::default())]);
    let dir = tdir("m3-precancel");
    let cancel = SideCancel::new();
    cancel.cancel();
    let mut idm = std::collections::HashMap::new();
    idm.insert(std::sync::Arc::<str>::from("<vol@x>"), 0usize);
    let t0 = std::time::Instant::now();
    let res = fetch_volume_articles(
        &servers,
        vec![ArticleReq {
            id: "<vol@x>".into(),
            age_days: 0,
            part: 1,
            file: u32::MAX,
        }],
        idm,
        &dir,
        &nzbkit::pool::BufPool::new(4),
        u64::MAX,
        Some(&cancel),
    )
    .await;
    assert!(res.is_err(), "a cancelled owner's fetch is refused");
    // Not "fast for a mute provider" - immediate. A dial to the
    // blackhole would cost seconds.
    assert!(
        t0.elapsed() < std::time::Duration::from_millis(200),
        "refusal should not dial; took {:?}",
        t0.elapsed()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// **The lease reserve, from the shape that needed it** (30 Aug 2026,
/// claim `sidefetch-lease-reserve-one`; the write-up and the ruling are
/// `research/SIDEFETCH-LEASE-2026-08-30.md`).
///
/// This test WAS the reproduction of the defect: it asserted that the
/// side pool dialled nothing, opened no connection and asked for no
/// article while the next job held the account at its cap, and it
/// carried a guard saying in place that it would need rewriting the day
/// the product decision was taken. That day was 30 Aug 2026, and the
/// option taken was B - reserve one permit per account for
/// post-processing fetches - so this is the same rig asserting the
/// opposite.
///
/// **What was wrong.** `strip_side_pool_seams` gives up `crc_steer`,
/// `arrival_ack`, `channel_gauge` and the line-cap steering wheel, and it
/// does not give up `lease` - which is correct, because a side pool
/// outside the accounting is a second full fleet on an account that
/// already has one. What it did not do was say what CLASS of work the
/// pool is: its workers took permits as a download, and
/// `runlife::worker` takes one BEFORE it dials. A recovery side-fetch
/// runs by construction on job A's post-download tail, which is exactly
/// when job B has started downloading, so job A's repair parked in
/// `HostLease::acquire` behind permits job B holds for the whole of its
/// own run - and every retry parked the same way. A repair behind a long
/// job could not succeed, however often it was tried.
///
/// **What is asserted now.** The side pool takes the one permit
/// `handoff::POST_PROCESS_RESERVE` holds back and DRAINS THE SET, while
/// job B still holds every permit a download is allowed. And it takes
/// exactly one: the far end sees a single connection out of the six the
/// download's config asks for, because the reserve is one permit and not
/// a licence for a second fleet.
///
/// Asserted at the FAR END (`conns_open`, `serve_counts`) and not from
/// the client's own gauges, for `MockServer::conns_open`'s stated
/// reason: a test about which connections were made must not take the
/// client's bookkeeping on trust.
#[tokio::test]
async fn a_side_fetch_takes_the_reserved_permit_behind_the_next_jobs_download() {
    use nzbkit::mock::{Chaos, MockServer};
    use nzbkit::pool::ArticleReq;
    use nzbkit::pool::handoff::ConnBudget;

    // Wide enough that "one connection" is a real restraint rather than
    // the only thing the pool could have done anyway.
    const CAP: usize = 6;
    const PARTS: u32 = 12;
    let chunk = vec![b'v'; 256];
    let total = chunk.len() as u64 * PARTS as u64;
    let mut arts = std::collections::HashMap::new();
    let mut ids = Vec::new();
    let mut idm = std::collections::HashMap::new();
    for p in 1..=PARTS {
        let id = format!("<r{p}@reserve>");
        arts.insert(
            id.clone(),
            nzbkit::yenc::encode(
                "reserve.vol000+012.par2",
                total,
                Some((p, PARTS)),
                (p as u64 - 1) * chunk.len() as u64 + 1,
                &chunk,
            ),
        );
        idm.insert(std::sync::Arc::<str>::from(id.as_str()), 0usize);
        ids.push(ArticleReq {
            id: id.as_str().into(),
            age_days: 0,
            part: p,
            file: u32::MAX,
        });
    }
    // Slow enough that a fleet allowed to open would be holding several
    // sockets at once while the far end is sampled.
    let srv = MockServer::start(
        arts,
        Chaos {
            delay_ms: 60,
            ..Default::default()
        },
    )
    .await;

    // The daemon's per-account budget, exactly as `get::fleet` builds
    // it: one lease per account, sized to the fleet the DOWNLOAD spawns.
    let budget = ConnBudget::new();
    let sc = srv.server_config();
    let lease = budget.lease(&ConnBudget::key(&sc), CAP);
    assert_eq!(
        lease.download_cap(),
        CAP - nzbkit::pool::handoff::POST_PROCESS_RESERVE,
        "the account holds one permit back from every download"
    );

    // Job B: a download that has taken everything a download is allowed
    // and is going to hold it for as long as it runs.
    let mut job_b = Vec::new();
    for _ in 0..lease.download_cap() {
        job_b.push(lease.acquire().await);
    }
    assert_eq!(lease.snapshot(), (CAP - 1, CAP));
    // And it cannot reach past that into the reserve, however many
    // workers it spawned - this is the connection the download pays.
    let l2 = lease.clone();
    let job_b_surplus = tokio::spawn(async move { l2.acquire().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(
        !job_b_surplus.is_finished(),
        "a download may not take the post-processing reserve"
    );

    // Job A's recovery side-fetch, on a config cloned from job A's own
    // download fleet - which is what `run_set_repair` passes down, width
    // and all. `fetch_volume_articles` applies `strip_side_pool_seams`
    // itself, so this is the shape a caller really hands it.
    let servers = vec![(
        sc,
        nzbkit::pool::PoolConfig {
            connections: CAP,
            lease: Some(lease.clone()),
            ..Default::default()
        },
    )];
    assert!(
        servers[0].1.lease.is_some(),
        "the strip keeps `lease`: a side pool outside the accounting is          a second fleet on an account that already has one"
    );

    let dir = tdir("lease-reserve");
    let dir2 = dir.clone();
    let t0 = std::time::Instant::now();
    let fetch = tokio::spawn(async move {
        fetch_volume_articles(
            &servers,
            ids,
            idm,
            &dir2,
            &nzbkit::pool::BufPool::new(8),
            u64::MAX,
            None,
        )
        .await
    });

    // Sample the FAR END while it runs: the reserve is ONE permit, so
    // one connection is what the provider may ever see from this pool
    // on top of the download's own.
    //
    // Deadlined, and the deadline is the starvation assertion this test
    // used to make from the other side: without the reserve this pool
    // never dials at all, and the only thing that ends the fetch is the
    // 300 s side-fetch stall watchdog - a five-minute red that says
    // "timed out" rather than "starved".
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut peak = 0usize;
    while !fetch.is_finished() {
        assert!(
            std::time::Instant::now() < deadline,
            "STARVED: the side pool is still parked while job B holds the              account at its download cap. It should be draining on the              reserved permit; the far end has seen {} connection(s)",
            srv.conns_open()
        );
        peak = peak.max(srv.conns_open());
        assert!(
            lease.snapshot().0 <= CAP,
            "the account may never hold more than its cap"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let (failures, paths) = tokio::time::timeout(std::time::Duration::from_secs(30), fetch)
        .await
        .expect("the side-fetch drains on the reserved permit")
        .expect("join")
        .expect("harvest succeeds");
    assert!(
        job_b_surplus.is_finished() || !job_b.is_empty(),
        "job B was never disturbed"
    );
    assert_eq!(
        failures.total(),
        0,
        "every recovery article landed while job B held the account at          its download cap - which is the whole difference between a          repair that finishes and one that cannot succeed"
    );
    assert_eq!(paths.len(), 1, "the volume file was assembled");
    assert_eq!(
        peak, 1,
        "the reserve is ONE permit: the side pool asked for {CAP}          connections and may hold exactly one, so the provider never          sees a second fleet on this account"
    );
    assert!(
        !srv.serve_counts().is_empty(),
        "and it really did ask the provider for articles"
    );
    assert!(
        t0.elapsed() < std::time::Duration::from_secs(20),
        "one permit drains the set slower, not never; took {:?}",
        t0.elapsed()
    );
    assert_eq!(
        lease.snapshot(),
        (CAP - 1, CAP),
        "and the side pool gave its permit back"
    );

    job_b_surplus.abort();
    let _ = job_b_surplus.await;
    drop(job_b);
    let _ = std::fs::remove_dir_all(&dir);
}

/// **What the repair side-fetch's WIDTH is, which is what decides the
/// cost of the three options above** (claim `sidefetch-lease-starvation`).
///
/// It is easy to read the side pool as "the tiny one-connection-per-
/// server pool" - `side_pool_servers` says exactly that in its own doc
/// - and for the M2c.5 speculative prefetch it is true. The REPAIR
/// path does not go through that helper. `repair::fetch_volumes` hands
/// `fetch_volume_articles` the DOWNLOAD's configs verbatim, and
/// `strip_side_pool_seams` - the one thing every side-fetch does go
/// through - gives up six seams and never touches `connections`.
///
/// So a recovery side-fetch runs at the MAIN FLEET's width, and the
/// overshoot from simply clearing `lease` is not one connection per
/// server, it is a whole second fleet on an account that already has
/// one: 2x the provider's cap, which is the "502 connection limit
/// reached" wall the lease exists to stay inside.
///
/// Pinned rather than left as a reading, because whichever option is
/// taken has to know this number, and because a later `connections = 1`
/// added to the strip would change the answer with nothing to say so.
#[tokio::test]
async fn the_repair_side_fetch_runs_at_the_main_fleets_width() {
    use nzbkit::mock::{Chaos, MockServer};
    use nzbkit::pool::ArticleReq;

    const WIDTH: usize = 6;
    const PARTS: u32 = 40;
    let chunk = vec![b'r'; 512];
    let total = chunk.len() as u64 * PARTS as u64;
    let mut arts = std::collections::HashMap::new();
    let mut ids = Vec::new();
    let mut idm = std::collections::HashMap::new();
    for p in 1..=PARTS {
        let id = format!("<w{p}@width>");
        let begin = (p as u64 - 1) * chunk.len() as u64 + 1;
        arts.insert(
            id.clone(),
            nzbkit::yenc::encode(
                "width.vol000+040.par2",
                total,
                Some((p, PARTS)),
                begin,
                &chunk,
            ),
        );
        idm.insert(std::sync::Arc::<str>::from(id.as_str()), 0usize);
        ids.push(ArticleReq {
            id: id.as_str().into(),
            age_days: 0,
            part: p,
            file: u32::MAX,
        });
    }
    // Slow enough that the whole fleet is up and holding sockets at once
    // while the run lasts, so the far end's count is the real width.
    let srv = MockServer::start(
        arts,
        Chaos {
            delay_ms: 300,
            ..Default::default()
        },
    )
    .await;

    // A DOWNLOAD's config, not `side_pool_servers`': this is the shape
    // `repair::fetch_volumes` passes down. No lease - the point here is
    // the width, and the starvation is the test above.
    let servers = vec![(
        srv.server_config(),
        nzbkit::pool::PoolConfig {
            connections: WIDTH,
            ..Default::default()
        },
    )];
    let dir = tdir("side-width");
    let dir2 = dir.clone();
    let fetch = tokio::spawn(async move {
        fetch_volume_articles(
            &servers,
            ids,
            idm,
            &dir2,
            &nzbkit::pool::BufPool::new(8),
            u64::MAX,
            None,
        )
        .await
    });

    // Sample the FAR END, for `MockServer::conns_open`'s reason.
    let mut peak = 0usize;
    while !fetch.is_finished() {
        peak = peak.max(srv.conns_open());
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    let (failures, _paths) = tokio::time::timeout(std::time::Duration::from_secs(30), fetch)
        .await
        .expect("the width probe completes")
        .expect("join")
        .expect("harvest succeeds");
    assert_eq!(failures.total(), 0, "every part landed");
    assert!(
        peak > 1,
        "the repair side-fetch is NOT a one-connection pool - it opened \
         {peak} of the {WIDTH} the download config asked for. If this \
         ever reads 1, `strip_side_pool_seams` has started narrowing \
         `connections` and the lease-overshoot pricing changes with it"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// **The number the reserve is, on its own** (claim
/// `sidefetch-lease-starvation`, and since 30 Aug 2026
/// `handoff::POST_PROCESS_RESERVE`). The handoff that raised the option
/// said it was "correct in principle, and it needs a number nobody has
/// measured". This is the measurement, and the number is ONE. It is kept
/// after the reserve shipped because it is the only test that asks the
/// question the number answers - can a side pool drain a whole recovery
/// set on a single permit - rather than whether the reserve is wired.
///
/// The starving pool is six workers wide (see the width pin above), so
/// the tempting reading is that a reserve has to be six - a whole
/// second fleet's worth, which is the same overshoot as clearing
/// `lease` outright and would make the option pointless. It does not.
/// A side pool does not need its configured width to make progress, it
/// needs a permit: one worker that can dial drains the whole recovery
/// set, slower, and the other five sit in `acquire` and retire when the
/// run ends. The difference between one permit and none is the
/// difference between a repair that finishes and a repair that cannot
/// succeed however often it is retried.
///
/// So the price of removing the "cannot succeed" property is ONE
/// connection held back from the download, per account - not a fleet,
/// and not a number that has to be tuned per provider.
#[tokio::test]
async fn one_spare_permit_is_enough_for_a_side_fetch_to_finish() {
    use nzbkit::mock::{Chaos, MockServer};
    use nzbkit::pool::ArticleReq;
    use nzbkit::pool::handoff::ConnBudget;

    const CAP: usize = 6;
    let payload = b"one permit is enough";
    let mut arts = std::collections::HashMap::new();
    let mut ids = Vec::new();
    let mut idm = std::collections::HashMap::new();
    for p in 1..=8u32 {
        let id = format!("<s{p}@spare>");
        arts.insert(
            id.clone(),
            nzbkit::yenc::encode(
                "spare.vol000+008.par2",
                payload.len() as u64 * 8,
                Some((p, 8)),
                (p as u64 - 1) * payload.len() as u64 + 1,
                payload,
            ),
        );
        idm.insert(std::sync::Arc::<str>::from(id.as_str()), 0usize);
        ids.push(ArticleReq {
            id: id.as_str().into(),
            age_days: 0,
            part: p,
            file: u32::MAX,
        });
    }
    let srv = MockServer::start(arts, Chaos::default()).await;
    let budget = ConnBudget::new();
    let sc = srv.server_config();
    let lease = budget.lease(&ConnBudget::key(&sc), CAP);

    // Job B holds all but one - which is what the reserve leaves it.
    let mut job_b = Vec::new();
    for _ in 0..CAP - 1 {
        job_b.push(lease.acquire().await);
    }
    assert_eq!(lease.snapshot(), (CAP - 1, CAP), "one slot spare");

    let servers = vec![(
        sc,
        nzbkit::pool::PoolConfig {
            connections: CAP,
            lease: Some(lease.clone()),
            ..Default::default()
        },
    )];
    let dir = tdir("one-spare");
    let (failures, paths) = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        fetch_volume_articles(
            &servers,
            ids,
            idm,
            &dir,
            &nzbkit::pool::BufPool::new(8),
            u64::MAX,
            None,
        ),
    )
    .await
    .expect("one free permit is enough to drain a recovery set")
    .expect("harvest succeeds");
    assert_eq!(
        failures.total(),
        0,
        "every article landed on the single permit the reserve leaves"
    );
    assert_eq!(paths.len(), 1, "the volume was assembled");
    drop(job_b);
    let _ = std::fs::remove_dir_all(&dir);
}

/// **The two seams a side pool inherited from the download that are
/// about the DAEMON rather than about fetching** (claim
/// `sidefetch-seam-residue`, out of the `sidefetch-lease-starvation`
/// lane's item 1b).
///
/// `strip_side_pool_seams` gave up six seams and left three. Two of
/// them are pinned here; the third, `connections`, is deliberately NOT
/// - a recovery fetch's width is a product trade (a one-connection
/// fetch of 8.5 GB is slow) and `the_repair_side_fetch_runs_at_the_
/// main_fleets_width` above is the pin that says what it is today.
///
/// * **`live`** - the dashboard's per-server gauges. Post-download
///   recovery traffic was charged to the download's own server row, so
///   a number on a screen was not what it said it was.
/// * **`handoff`** - the run's per-run hand-over latch, which the
///   daemon's queue runner waits on to start the NEXT job.
///   `Shared::note_idle_after_dry` latches it the first time a level-0
///   worker is idle past its own queue-dry, and for a side pool that is
///   the ordinary end of a two-volume fetch. On the repair path the
///   latch is inert by luck (`net_done` is sent before settle and the
///   runner selects on it `biased`, so nothing is waiting by then); on
///   the M2c.5 speculative prefetch path, which runs MID-DOWNLOAD, the
///   runner IS waiting, so a prefetch rung going dry starts the next
///   job while the download's fleet is at full width.
///
/// **Control and treatment, because a "did not latch" assertion over a
/// rig that never reaches idle-after-dry proves nothing.** Arm A runs
/// the SAME articles through `nzbkit::pool::fetch_all_multi` on the
/// UNSTRIPPED download-shaped config - the pre-31-Aug-2026 behaviour,
/// and the measurement the fix was made on - and requires the latch to
/// fire and the gauges to move. Arm B runs them through
/// `fetch_volume_articles`, which is the one driver every side-fetch
/// goes through, and requires neither. If arm A ever stops firing this
/// test has stopped testing anything and the rig needs rebuilding, not
/// arm B relaxing.
#[tokio::test]
async fn a_side_fetch_moves_neither_the_dashboard_nor_the_hand_over_signal() {
    use nzbkit::mock::{Chaos, MockServer};
    use nzbkit::pool::ArticleReq;
    use std::sync::atomic::Ordering;

    // Wide enough, and slow enough, that a worker really does finish
    // its share while others are still in flight - which is the
    // idle-past-queue-dry condition the latch hangs off.
    const WIDTH: usize = 6;
    const PARTS: u32 = 40;
    let chunk = vec![b's'; 512];
    let total = chunk.len() as u64 * PARTS as u64;
    let mut arts = std::collections::HashMap::new();
    let mut ids = Vec::new();
    let mut idm = std::collections::HashMap::new();
    for p in 1..=PARTS {
        let id = format!("<s{p}@seam>");
        arts.insert(
            id.clone(),
            nzbkit::yenc::encode(
                "seam.vol000+040.par2",
                total,
                Some((p, PARTS)),
                (p as u64 - 1) * chunk.len() as u64 + 1,
                &chunk,
            ),
        );
        idm.insert(std::sync::Arc::<str>::from(id.as_str()), 0usize);
        ids.push(ArticleReq {
            id: id.as_str().into(),
            age_days: 0,
            part: p,
            file: u32::MAX,
        });
    }
    let srv = MockServer::start(
        arts,
        Chaos {
            delay_ms: 120,
            ..Default::default()
        },
    )
    .await;
    let sc = srv.server_config();

    // The shape `repair::fetch_volumes` hands down: the DOWNLOAD's own
    // pool config, gauges and hand-over signal and all.
    let download_shaped =
        |live: &Arc<nzbkit::pool::LiveStats>, sig: &Arc<nzbkit::pool::handoff::HandoffSignal>| {
            vec![(
                sc.clone(),
                nzbkit::pool::PoolConfig {
                    connections: WIDTH,
                    live: Some(live.clone()),
                    handoff: Some(sig.clone()),
                    ..Default::default()
                },
            )]
        };

    // ---- Arm A: the control. No strip, so this is what a side pool
    // did before 31 Aug 2026, and it is what proves the rig reaches the
    // condition at all.
    let live_a =
        nzbkit::pool::LiveStats::for_servers(&[(sc.clone(), nzbkit::pool::PoolConfig::default())]);
    let sig_a = nzbkit::pool::handoff::HandoffSignal::new();
    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    let servers_a = download_shaped(&live_a, &sig_a);
    let ids_a = ids.clone();
    let raw =
        tokio::spawn(async move { nzbkit::pool::fetch_all_multi(&servers_a, ids_a, tx).await });
    let drain = tokio::spawn(async move {
        let mut done = 0usize;
        while let Some(o) = rx.recv().await {
            if matches!(o, nzbkit::pool::FetchOutcome::Done { .. }) {
                done += 1;
            }
        }
        done
    });
    tokio::time::timeout(std::time::Duration::from_secs(60), raw)
        .await
        .expect("the control arm completes")
        .expect("join");
    assert_eq!(
        drain.await.expect("join"),
        PARTS as usize,
        "the control arm did not fetch the set, so it proves nothing"
    );
    assert!(
        sig_a.is_latched(),
        "CONTROL FAILED: a pool carrying the download's hand-over signal \
         did not latch it, so this rig never reached idle-past-queue-dry \
         and arm B below is vacuous. Rebuild the rig (more parts, more \
         delay); do NOT relax arm B"
    );
    assert!(
        live_a.servers[0].bytes.load(Ordering::Relaxed) > 0
            && live_a.servers[0].articles_tried.load(Ordering::Relaxed) > 0,
        "CONTROL FAILED: a pool carrying the download's LiveStats moved no \
         gauge, so arm B's zeroes below say nothing"
    );

    // ---- Arm B: the treatment. The same articles through the driver
    // every side-fetch goes through.
    let live_b =
        nzbkit::pool::LiveStats::for_servers(&[(sc.clone(), nzbkit::pool::PoolConfig::default())]);
    let sig_b = nzbkit::pool::handoff::HandoffSignal::new();
    let servers_b = download_shaped(&live_b, &sig_b);
    let dir = tdir("seam-residue");
    let (failures, paths) = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        fetch_volume_articles(
            &servers_b,
            ids,
            idm,
            &dir,
            &nzbkit::pool::BufPool::new(8),
            u64::MAX,
            None,
        ),
    )
    .await
    .expect("the side-fetch completes")
    .expect("harvest succeeds");
    assert_eq!(failures.total(), 0, "the side-fetch did not fetch the set");
    assert_eq!(paths.len(), 1, "the volume was assembled");
    assert!(
        !srv.serve_counts().is_empty(),
        "and it really did ask the provider for articles"
    );
    assert!(
        !sig_b.is_latched(),
        "the side pool told the daemon the DOWNLOAD's fleet is going idle. \
         On the speculative-prefetch path that starts the next job while \
         this one's fleet is at full width"
    );
    assert_eq!(
        live_b.servers[0].bytes.load(Ordering::Relaxed),
        0,
        "post-download recovery traffic was charged to the download's own \
         server row"
    );
    assert_eq!(
        live_b.servers[0].articles_tried.load(Ordering::Relaxed),
        0,
        "the side-fetch's articles were counted as the download's"
    );
    assert_eq!(
        live_b.servers[0].connected_peak.load(Ordering::Relaxed),
        0,
        "the side pool's sockets were counted on the download's row"
    );
    assert!(
        live_b.events.lock().unwrap().is_empty(),
        "the side pool wrote run notes onto the download's event feed: {:?}",
        live_b
            .events
            .lock()
            .unwrap()
            .iter()
            .map(|e| (e.kind, e.detail.clone()))
            .collect::<Vec<_>>()
    );
    // And at the CONFIG level, through the other of the two ways a side
    // pool is built. This arm cannot go vacuous the way the run-level
    // ones can, and it covers the prefetch path - the one where the
    // hand-over latch is not inert.
    let stripped = side_pool_servers(&download_shaped(&live_b, &sig_b));
    let pc = &stripped[0].1;
    assert!(
        pc.live.is_none(),
        "the prefetch side pool feeds the dashboard"
    );
    assert!(
        pc.handoff.is_none(),
        "the prefetch side pool holds the download's hand-over signal, and \
         it runs MID-DOWNLOAD - so its own queue-dry starts the next job"
    );
    // The one seam that is NOT given up, and the reason: a side pool
    // outside the accounting is a second fleet on an account that
    // already has one.
    let leased = side_pool_servers(&[(
        sc.clone(),
        nzbkit::pool::PoolConfig {
            lease: Some(nzbkit::pool::handoff::ConnBudget::new().lease("h", 4)),
            ..Default::default()
        },
    )]);
    assert!(leased[0].1.lease.is_some(), "the strip gave up `lease`");
    assert_eq!(
        leased[0].1.lease_class,
        nzbkit::pool::handoff::LeaseClass::PostProcess,
        "the strip stopped marking the side pool as post-processing"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
