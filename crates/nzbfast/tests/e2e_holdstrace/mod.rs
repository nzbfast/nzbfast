//! `NZBFAST_HOLDS_TRACE` (23 Aug 2026): the bench rig's HOLDS
//! `live_max_mb` is a max over the 2 Hz `[holds-trace]` samples this
//! switch turns on. A child module so e2e.rs stays inside its size-gate
//! baseline (the e2e_sample pattern: harness through `super::*`).

use super::*;

/// Store-mode RAR set, no par2 (so no `have_par2` guard is owed): with
/// the switch set the job sampler prints `[holds-trace] holds N MB`
/// lines, at least one of them, every one parseable the way
/// handoffq.sh parses it (`awk '{print $3}'` after the tag). Without
/// the switch it prints none - the line is off by default.
#[tokio::test(flavor = "multi_thread")]
async fn holds_trace_is_off_by_default_and_prints_mb_samples_when_set() {
    // par2-gate: rar_release(_, false) builds no par2 set, so par2 never runs
    let (fx, inner, _vols) = rar_release("holdstrace", false);
    // A slow server: the set is under 1 MB and an unshaped loopback
    // finishes it in ~200 ms, inside the sampler's first 500 ms period,
    // so the job would end before the trace's first sample is due.
    let chaos = Chaos {
        delay_ms: 300,
        ..Chaos::default()
    };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();

    let (c, n, o) = (cfg.clone(), nzb.clone(), fx.dir.join("out-off"));
    let (log_off, ok) = tokio::task::spawn_blocking(move || run_get(&c, &n, &o, &[]))
        .await
        .unwrap();
    assert!(ok, "get failed:\n{log_off}");
    assert!(
        !log_off.contains("[holds-trace]"),
        "trace must be off by default:\n{log_off}"
    );

    let out = fx.dir.join("out-on");
    let o = out.clone();
    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get(&cfg, &nzb, &o, &[("NZBFAST_HOLDS_TRACE", "1")])
    })
    .await
    .unwrap();
    assert!(ok, "get failed:\n{log}");
    let samples: Vec<u64> = log
        .lines()
        .filter_map(|l| l.split("[holds-trace] holds ").nth(1))
        .map(|rest| {
            let mut w = rest.split_whitespace();
            let mb: u64 = w.next().unwrap().parse().expect("holds MB is an integer");
            assert_eq!(w.next(), Some("MB"), "unit word the rig greps for");
            mb
        })
        .collect();
    assert!(
        !samples.is_empty(),
        "no [holds-trace] sample printed:\n{log}"
    );
    eprintln!("holds-trace samples: {samples:?}");
    assert_eq!(std::fs::read(out.join("movie.mkv")).unwrap(), inner);
}
