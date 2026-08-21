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
    assert_eq!(failures, 0, "the one article was served and decoded");
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
