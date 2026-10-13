//! A dead post that STALLS rather than resolving: every article absent
//! everywhere, one server refusing at once and the others refusing
//! slowly, so the stall watchdog fires before any one article has been
//! refused by every server.
//!
//! The live shape (12 Oct 2026, five real providers, synthetic dead
//! posts whose every message-id never existed) went wrong twice: the verdict said no server had called
//! anything missing and classified the job as a connection fault, and
//! the tail then spent minutes fetching recovery volumes that could not
//! rebuild a payload of which nothing had landed. This leg drives both
//! through the real `get` path on the mock.
//!
//! A sibling-dir child module (harness through `super::*`) so `e2e.rs`
//! stays inside its size-gate baseline.

use super::*;

#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_dead_post_blames_the_post_and_skips_the_recovery_fetch() {
    let mut fx = Fixture::new("deadstall");
    // Nothing in `fx.articles`: every id below is absent on every server.
    let seg = |f: &str, n: u32, bytes: u64| (format!("{f}-{n}@dead"), bytes, n);
    for f in 0..20 {
        let name = format!("dead.part{:02}.rar", f + 1);
        let segs = (1..=100).map(|n| seg(&name, n, 716_800)).collect();
        fx.nzb_files.push((name, segs));
    }
    fx.nzb_files
        .push(("dead.par2".into(), vec![seg("dead.par2", 1, 40_000)]));
    for (name, n) in [("dead.vol00+10.par2", 12u32), ("dead.vol10+20.par2", 24)] {
        let segs = (1..=n).map(|k| seg(name, k, 716_800)).collect();
        fx.nzb_files.push((name.into(), segs));
    }
    let refuse = |missing_delay_ms| Chaos {
        echo_missing_id: true,
        missing_delay_ms,
        ..Default::default()
    };
    let fast = MockServer::start(HashMap::new(), refuse(0)).await;
    let slow_a = MockServer::start(HashMap::new(), refuse(200)).await;
    let slow_b = MockServer::start(HashMap::new(), refuse(200)).await;
    let cfg = fx.write_config(&[&fast, &slow_a, &slow_b]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let t0 = std::time::Instant::now();
    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get(
            &cfg,
            &nzb,
            &out,
            &[
                ("NZBFAST_STALL_ABORT_SECS", "12"),
                ("NZBFAST_NO_ENRICH", "1"),
            ],
        )
    })
    .await
    .unwrap();
    let secs = t0.elapsed().as_secs_f64();
    eprintln!("DEADSTALL {secs:.1}s\n{log}");
    assert!(!ok, "{log}");
    assert!(
        log.contains("download stalled"),
        "the leg must reproduce the stall, or it proves nothing: {log}"
    );
    let verdict = log
        .lines()
        .find(|l| l.contains("Error: "))
        .unwrap_or_else(|| panic!("no error line: {log}"));
    assert!(
        verdict.contains("Error: download incomplete: every server refused this post"),
        "{verdict}"
    );
    assert!(
        !log.contains("No server said any article was missing"),
        "{log}"
    );
    assert!(
        log.contains("not fetching 2 deferred recovery volume(s)"),
        "{log}"
    );
    assert!(!log.contains("for disk repair"), "{log}");
    assert!(
        log.contains("not fetching 2 deferred recovery volume(s): no payload article landed"),
        "{log}"
    );
}
