//! §106 phase 3: unit tests for the pure helpers and small
//! Daemon-backed functions in serve/tasks.rs. StallTracker basics live
//! in `stall_tests`; only the edges it misses are covered here.

use super::*;
use serde_json::json;
use std::time::{Duration, Instant};

fn tdir(name: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("nzbfast-tsk-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn mkjob(name: &str, identity: &str) -> Job {
    let mut j = super::super::job_from_json(&json!({
        "nzo_id": "tsk1",
        "name": name,
        "nzb_path": "/spool/tsk1.nzb",
        "out_dir": "/dl/tsk1",
        "state": "Queued",
    }))
    .expect("job_from_json");
    j.identity_name = identity.to_string();
    j
}

fn facts(res: Option<&str>, complete: bool) -> nzbkit::mediaprobe::MediaFacts {
    nzbkit::mediaprobe::MediaFacts {
        res: res.map(|s| s.to_string()),
        complete,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------
// 1. lane_kind
// ---------------------------------------------------------------------

#[cfg(feature = "indexer")]
#[test]
fn lane_kind_maps_the_four_lanes_and_nothing_else() {
    use crate::wall::Kind;
    assert_eq!(super::lane_kind("tv"), Kind::Tv);
    assert_eq!(super::lane_kind("movie"), Kind::Movie);
    assert_eq!(super::lane_kind("music"), Kind::Music);
    assert_eq!(super::lane_kind("book"), Kind::Book);
    // Anything else - empty, wrong case, unknown - is Other, which the
    // enricher stamps without a provider call.
    assert_eq!(super::lane_kind(""), Kind::Other);
    assert_eq!(super::lane_kind("TV"), Kind::Other);
    assert_eq!(super::lane_kind("other"), Kind::Other);
}

// ---------------------------------------------------------------------
// 2. watch_fail_id
// ---------------------------------------------------------------------

#[test]
fn watch_fail_id_is_an_opaque_16_hex_handle_of_the_full_path() {
    let a = super::watch_fail_id(std::path::Path::new("/a/same.nzb"));
    assert_eq!(a.len(), 16);
    assert!(
        a.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
    // Deterministic.
    assert_eq!(a, super::watch_fail_id(std::path::Path::new("/a/same.nzb")));
    // The FULL path is the identity: same basename, different dir.
    let b = super::watch_fail_id(std::path::Path::new("/b/same.nzb"));
    assert_ne!(a, b);
    // A digest, never the path itself.
    assert!(!a.contains("same") && !a.contains("nzb"));
    assert!(!b.contains("same") && !b.contains("nzb"));
}

// ---------------------------------------------------------------------
// 3. watch_fail_kind edges
// ---------------------------------------------------------------------

#[test]
fn watch_fail_kind_matches_exactly_except_the_kept_prefix() {
    use super::watchfail;
    // Only KEPT is starts_with; the others are exact equality, so a
    // message merely CONTAINING one stays "rejected".
    let wrapped = format!("note: {} (seen twice)", watchfail::TRUNCATED);
    assert_eq!(super::watch_fail_kind(&wrapped), "rejected");
    assert_eq!(super::watch_fail_kind(""), "rejected");
    let kept = format!("{}: Permission denied (os error 13)", watchfail::KEPT);
    assert_eq!(super::watch_fail_kind(&kept), "kept");
}

// ---------------------------------------------------------------------
// 4. media_claim_name
// ---------------------------------------------------------------------

#[test]
fn media_claim_name_prefers_a_non_empty_identity() {
    let j = mkjob("posted.name", "");
    assert_eq!(super::media_claim_name(&j), "posted.name");
    let j = mkjob("posted.name", "Canonical.Name-GRP");
    assert_eq!(super::media_claim_name(&j), "Canonical.Name-GRP");
    // Whitespace is non-empty: no trimming happens here.
    let j = mkjob("posted.name", "   ");
    assert_eq!(super::media_claim_name(&j), "   ");
}

// ---------------------------------------------------------------------
// 5. media_settled
// ---------------------------------------------------------------------

#[test]
fn media_settled_four_way_truth_table() {
    // No media at all.
    let j = mkjob("x", "");
    assert!(!super::media_settled(&j));
    // Complete but nothing to show (any() false).
    let mut j = mkjob("x", "");
    j.media = Some(facts(None, true));
    assert!(!super::media_settled(&j));
    // Complete and showing, but owed a re-judge.
    let mut j = mkjob("x", "");
    j.media = Some(facts(Some("1080p"), true));
    j.media_rejudge = true;
    assert!(!super::media_settled(&j));
    // Complete, showing, no re-judge owed: settled.
    let mut j = mkjob("x", "");
    j.media = Some(facts(Some("1080p"), true));
    assert!(super::media_settled(&j));
}

// ---------------------------------------------------------------------
// 6. latch_media
// ---------------------------------------------------------------------

#[test]
fn latch_media_never_downgrades_and_reports_real_changes() {
    use std::sync::{Arc, Mutex};
    // Empty facts over an existing answer: refused, answer untouched.
    let job = Arc::new(Mutex::new(mkjob("x", "")));
    job.lock_ok().media = Some(facts(Some("2160p"), true));
    assert!(!super::latch_media(&job, facts(None, false)));
    assert_eq!(
        job.lock_ok().media.as_ref().unwrap().res.as_deref(),
        Some("2160p")
    );
    // Identical facts: no change to report.
    assert!(!super::latch_media(&job, facts(Some("2160p"), true)));
    // Empty facts over None DO latch (the "probe ran, saw nothing yet"
    // record is itself information).
    let job = Arc::new(Mutex::new(mkjob("x", "")));
    assert!(super::latch_media(&job, facts(None, false)));
    assert!(job.lock_ok().media.is_some());
    // A mismatch list writes and returns true.
    let mut f = facts(Some("1080p"), true);
    f.mismatch.push(nzbkit::mediaprobe::facts::Mismatch {
        field: nzbkit::mediaprobe::facts::Field::Resolution,
        claimed: "2160p".to_string(),
        actual: "1080p".to_string(),
    });
    assert!(super::latch_media(&job, f.clone()));
    assert_eq!(job.lock_ok().media.as_ref(), Some(&f));
}

// ---------------------------------------------------------------------
// 7. StallTracker edges
// ---------------------------------------------------------------------

#[test]
fn stall_opens_exactly_at_the_threshold_and_reports_since() {
    let t0 = Instant::now();
    let mut s = StallTracker::new(Duration::from_secs(10));
    assert!(s.observe(t0, Some(("a", "job-a")), 100).is_none());
    // >= semantics: exactly T after the baseline opens the episode.
    match s.observe(t0 + Duration::from_secs(10), Some(("a", "job-a")), 100) {
        Some(StallEvent::Opened { idle_secs, since }) => {
            assert_eq!(idle_secs, 10);
            assert_eq!(since, t0);
        }
        _ => panic!("expected Opened exactly at the threshold"),
    }
}

#[test]
fn stall_bytes_going_backwards_count_as_progress() {
    let t0 = Instant::now();
    let tick = |secs: u64| t0 + Duration::from_secs(secs);
    let mut s = StallTracker::new(Duration::from_secs(10));
    assert!(s.observe(t0, Some(("a", "job-a")), 500).is_none());
    // A LOWER total is still "total != last": the clock resets.
    assert!(s.observe(tick(5), Some(("a", "job-a")), 400).is_none());
    // 10s from t0 but only 5s from the backwards move: still quiet.
    assert!(s.observe(tick(10), Some(("a", "job-a")), 400).is_none());
    assert!(matches!(
        s.observe(tick(15), Some(("a", "job-a")), 400),
        Some(StallEvent::Opened { idle_secs: 10, .. })
    ));
    // And an open episode is CLEARED by a backwards move too.
    assert!(matches!(
        s.observe(tick(20), Some(("a", "job-a")), 300),
        Some(StallEvent::Cleared { .. })
    ));
}

#[test]
fn stall_no_open_episode_means_silence_on_job_end() {
    let t0 = Instant::now();
    let tick = |secs: u64| t0 + Duration::from_secs(secs);
    let mut s = StallTracker::new(Duration::from_secs(10));
    // Never any job: nothing to say.
    assert!(s.observe(t0, None, 0).is_none());
    // A job that leaves BEFORE its episode opens ends silently.
    assert!(s.observe(tick(1), Some(("a", "job-a")), 100).is_none());
    assert!(s.observe(tick(5), None, 0).is_none());
    assert!(s.observe(tick(6), None, 0).is_none());
}

// ---------------------------------------------------------------------
// 8. prune_person_art
// ---------------------------------------------------------------------

#[cfg(feature = "indexer")]
fn art_file(dir: &std::path::Path, name: &str, len: usize, age_secs: u64) {
    let p = dir.join(name);
    std::fs::write(&p, vec![0u8; len]).unwrap();
    let t = std::time::SystemTime::now() - Duration::from_secs(age_secs);
    let f = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
    f.set_times(std::fs::FileTimes::new().set_accessed(t).set_modified(t))
        .unwrap();
}

#[cfg(feature = "indexer")]
#[test]
fn prune_person_art_spares_posters_and_leaves_an_under_cap_dir_alone() {
    let dir = tdir("prune-spare");
    // Posters and backdrops are never candidates, however old or large.
    art_file(&dir, "m_the_matrix_1999.jpg", 5000, 9000);
    art_file(&dir, "t_severance.bd.jpg", 5000, 9000);
    art_file(&dir, "p1.jpg", 100, 300);
    super::prune_person_art(&dir, 200);
    assert!(dir.join("m_the_matrix_1999.jpg").exists());
    assert!(dir.join("t_severance.bd.jpg").exists());
    assert!(dir.join("p1.jpg").exists());
    // Under the cap: a no-op even for headshots.
    art_file(&dir, "p2.jpg", 50, 100);
    super::prune_person_art(&dir, 10_000);
    assert!(dir.join("p1.jpg").exists());
    assert!(dir.join("p2.jpg").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(feature = "indexer")]
#[test]
fn prune_person_art_evicts_oldest_first_and_stops_at_the_cap() {
    let dir = tdir("prune-evict");
    art_file(&dir, "p1.jpg", 100, 3000); // oldest
    art_file(&dir, "p2.jpg", 100, 2000);
    art_file(&dir, "p3.jpg", 100, 1000); // newest
    art_file(&dir, "m_poster.jpg", 1000, 9000); // never counted
    // 300 headshot bytes over a 250 cap: evicting p1 alone reaches 200.
    super::prune_person_art(&dir, 250);
    assert!(!dir.join("p1.jpg").exists());
    assert!(dir.join("p2.jpg").exists());
    assert!(dir.join("p3.jpg").exists());
    assert!(dir.join("m_poster.jpg").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------
// 9. sample_ids
// ---------------------------------------------------------------------

fn epoch_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[test]
fn sample_ids_excludes_recovery_volumes_and_wraps_ids() {
    let dir = tdir("sample-ids");
    let now = epoch_now();
    let xml = format!(
        r#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file subject="data.bin yEnc (1/2)" date="{}">
  <groups><group>alt.binaries.test</group></groups>
  <segments>
   <segment bytes="1000" number="1">seg1@test</segment>
   <segment bytes="1000" number="2">seg2@test</segment>
  </segments>
 </file>
 <file subject="set.par2 yEnc (1/1)" date="{}">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="500" number="1">par2main@test</segment></segments>
 </file>
 <file subject="set.vol000+01.par2 yEnc (1/1)" date="{}">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="500" number="1">vol@test</segment></segments>
 </file>
</nzb>"#,
        now - 5 * 86_400 - 10,
        now - 2 * 86_400 - 10,
        now // if the volume leaked into the age, it would read 0
    );
    let path = dir.join("post.nzb");
    std::fs::write(&path, xml).unwrap();
    let (ids, age) = super::sample_ids(&path, 64).expect("sampled");
    assert!(ids.contains(&"<seg1@test>".to_string()));
    assert!(ids.contains(&"<seg2@test>".to_string()));
    // The base .par2 index IS sampled; recovery volumes are not.
    assert!(ids.contains(&"<par2main@test>".to_string()));
    assert!(!ids.iter().any(|i| i.contains("vol@test")));
    // Age is the minimum over the sampled files: 2 days, not 5, not 0.
    assert_eq!(age, 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sample_ids_answers_none_for_volume_only_or_unreadable_posts() {
    let dir = tdir("sample-none");
    let xml = format!(
        r#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file subject="set.vol000+01.par2 yEnc (1/1)" date="{}">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="500" number="1">vol@test</segment></segments>
 </file>
</nzb>"#,
        epoch_now() - 86_400
    );
    let path = dir.join("vols.nzb");
    std::fs::write(&path, xml).unwrap();
    assert!(super::sample_ids(&path, 8).is_none());
    assert!(super::sample_ids(&dir.join("missing.nzb"), 8).is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------
// 10. update_tune_hint
// ---------------------------------------------------------------------

fn srv(host: &str, block: Option<u64>) -> nzbkit::config::ServerConfig {
    nzbkit::config::ServerConfig {
        host: host.into(),
        port: 563,
        tls: true,
        username: None,
        password: None,
        connections: 20,
        pin_connections: false,
        rcvbuf: None,
        level: 0,
        group: None,
        retention_days: 0,
        block_bytes: block,
        block_account: false,
        bind_ip: None,
        socks5: None,
        enabled: true,
        warm_pool: false,
        idle_release_secs: None,
        idle_keep: None,
        max_source_ips: None,
    }
}

fn tuned(gbps: f64, asked: usize, connections: usize) -> crate::conntune::Tuned {
    crate::conntune::Tuned {
        connections,
        granted: connections,
        asked,
        gbps,
        checked: 0,
        source: String::new(),
        suspect: false,
        limit: 0,
        v: 0,
        pending: None,
        buckets: Vec::new(),
        shaped: None,
        capped: None,
    }
}

#[test]
fn tune_hint_bands_stale_setting_well_short_and_clear() {
    let dir = tdir("tune-bands");
    let d = super::super::testutil::test_daemon(&dir);
    // Line speed is stored in bytes/s: 1 Gbps.
    d.line_speed.store(125_000_000, Ordering::Relaxed);
    let servers = vec![srv("news.a.example", None)];
    let map = |g: f64| {
        let mut m = std::collections::HashMap::new();
        m.insert("news.a.example".to_string(), tuned(g, 20, 20));
        m
    };
    // >110% of the line: the SETTING is called stale.
    super::update_tune_hint(&d, &servers, &map(1.2));
    assert!(d.tune_hint.lock_ok().contains("the setting looks low"));
    // <80%: well short, providers are the lever.
    super::update_tune_hint(&d, &servers, &map(0.5));
    assert!(d.tune_hint.lock_ok().contains("well short"));
    // In between: the hint clears.
    super::update_tune_hint(&d, &servers, &map(1.0));
    assert!(d.tune_hint.lock_ok().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tune_hint_block_accounts_never_gate_the_verdict() {
    let dir = tdir("tune-block");
    let d = super::super::testutil::test_daemon(&dir);
    d.line_speed.store(125_000_000, Ordering::Relaxed);
    // Only a block account: nothing is ever measured, so no verdict -
    // even with a tuned entry sitting there saying "well short".
    let block_only = vec![srv("block.example", Some(500 << 30))];
    let mut m = std::collections::HashMap::new();
    m.insert("block.example".to_string(), tuned(0.2, 20, 20));
    *d.tune_hint.lock_ok() = "stale words".to_string();
    super::update_tune_hint(&d, &block_only, &m);
    assert!(d.tune_hint.lock_ok().is_empty());
    // A block account BESIDE a measured server must not suppress the
    // verdict, even though the prober never gave it a tuned entry.
    let mixed = vec![
        srv("block.example", Some(500 << 30)),
        srv("news.a.example", None),
    ];
    let mut m = std::collections::HashMap::new();
    m.insert("news.a.example".to_string(), tuned(0.5, 20, 20));
    super::update_tune_hint(&d, &mixed, &m);
    assert!(d.tune_hint.lock_ok().contains("well short"));
    let _ = std::fs::remove_dir_all(&dir);
}

/// M7b.2 §5.7: a `block_account` server is invisible to the tuner in
/// exactly the way a prepaid block already was.
///
/// This is the half of the flag that is easy to get wrong. The prober
/// skips the server (its ladder would be tens of seconds of billed
/// article bodies); if THIS function's idea of a measurable server were
/// any wider, the flagged host would never carry a tuned entry and the
/// line-speed verdict would be suppressed for the whole install,
/// forever, with nothing in the log saying why. That bug shipped once
/// against block accounts; the shared `may_spend_on_measurement`
/// predicate is what stops the flag re-introducing it.
#[test]
fn tune_hint_ignores_servers_flagged_as_billed_per_byte() {
    let dir = tdir("tune-paid");
    let d = super::super::testutil::test_daemon(&dir);
    d.line_speed.store(125_000_000, Ordering::Relaxed);
    let paid = |host: &str| {
        let mut s = srv(host, None);
        s.block_account = true;
        s
    };
    // Flagged and alone: nothing measurable, so no verdict at all.
    let mut m = std::collections::HashMap::new();
    m.insert("paid.example".to_string(), tuned(0.2, 20, 20));
    *d.tune_hint.lock_ok() = "stale words".to_string();
    super::update_tune_hint(&d, &[paid("paid.example")], &m);
    assert!(
        d.tune_hint.lock_ok().is_empty(),
        "a flagged server is never probed, so it can never be the evidence"
    );
    // Flagged BESIDE a measured server: the verdict still lands, and it
    // is read off the measured one only.
    let mixed = vec![paid("paid.example"), srv("news.a.example", None)];
    let mut m = std::collections::HashMap::new();
    m.insert("news.a.example".to_string(), tuned(0.5, 20, 20));
    super::update_tune_hint(&d, &mixed, &m);
    assert!(
        d.tune_hint.lock_ok().contains("well short"),
        "one flagged server must not suppress the verdict for the install"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tune_hint_tips_tier_cap_unknown_asked_and_single_provider() {
    let dir = tdir("tune-tips");
    let d = super::super::testutil::test_daemon(&dir);
    d.line_speed.store(125_000_000, Ordering::Relaxed);
    // asked > connections: the account-tier tip names the exact pair.
    let two = vec![srv("news.a.example", None), srv("news.b.example", None)];
    let mut m = std::collections::HashMap::new();
    m.insert("news.a.example".to_string(), tuned(0.3, 32, 21));
    m.insert("news.b.example".to_string(), tuned(0.2, 8, 8));
    super::update_tune_hint(&d, &two, &m);
    {
        let h = d.tune_hint.lock_ok();
        assert!(h.contains("granted only 21 of the 32"));
        assert!(h.contains("news.a.example"));
    }
    // asked == 0 is a pre-field entry: unknown, so no tier claim - the
    // generic "faster provider" tip stands in.
    let mut m = std::collections::HashMap::new();
    m.insert("news.a.example".to_string(), tuned(0.3, 0, 6));
    m.insert("news.b.example".to_string(), tuned(0.2, 0, 6));
    super::update_tune_hint(&d, &two, &m);
    {
        let h = d.tune_hint.lock_ok();
        assert!(!h.contains("granted only"));
        assert!(h.contains("a faster provider"));
    }
    // A single measured provider gets the parallel-headroom tip.
    let one = vec![srv("news.a.example", None)];
    let mut m = std::collections::HashMap::new();
    m.insert("news.a.example".to_string(), tuned(0.5, 20, 20));
    super::update_tune_hint(&d, &one, &m);
    assert!(
        d.tune_hint
            .lock_ok()
            .contains("a second provider adds parallel headroom")
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------
// 11. download_idle
// ---------------------------------------------------------------------

#[test]
fn download_idle_requires_both_pipelines_quiet() {
    let dir = tdir("dl-idle");
    let d = super::super::testutil::test_daemon(&dir);
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mk_sidecar = || Sidecar {
        nzo_id: "s1".to_string(),
        hub: Arc::new(crate::StreamHub::default()),
        progress: Arc::new(AtomicU64::new(0)),
        cancelled: Arc::new(AtomicBool::new(false)),
        task: rt.spawn(async {}),
        borrowed: false,
    };
    // Neither running: idle.
    assert!(super::download_idle(&d));
    // Primary runner only.
    *d.started_at.lock_ok() = Some(Instant::now());
    assert!(!super::download_idle(&d));
    // Both.
    *d.sidecar.lock_ok() = Some(mk_sidecar());
    assert!(!super::download_idle(&d));
    // Sidecar only (the runner-tail window §77 stands down for).
    *d.started_at.lock_ok() = None;
    assert!(!super::download_idle(&d));
    *d.sidecar.lock_ok() = None;
    assert!(super::download_idle(&d));
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------
// 12. instant_arrivals
// ---------------------------------------------------------------------

#[cfg(feature = "indexer")]
#[test]
fn instant_arrivals_kicks_complete_hits_and_first_sighting_wins() {
    use nzbkit::index::WatchHit;
    let dir = tdir("instant");
    let d = super::super::testutil::test_daemon(&dir);
    d.instant_pending.lock_ok().insert(7, 111);
    // A complete hit leaves pending and kicks the watchlist pass.
    super::instant_arrivals(
        &d,
        vec![WatchHit {
            id: 7,
            name: "Show.S01E01.1080p-GRP".to_string(),
            complete: true,
        }],
        0,
        1000,
    );
    assert!(!d.instant_pending.lock_ok().contains_key(&7));
    assert!(
        d.instant_hint
            .lock_ok()
            .contains(&"Show.S01E01.1080p-GRP".to_string())
    );
    // An incomplete hit is stamped once; a later batch must NOT
    // re-stamp it (the first clock is what expires it).
    let hit = |now| {
        super::instant_arrivals(
            &d,
            vec![WatchHit {
                id: 9,
                name: "Still.Uploading".to_string(),
                complete: false,
            }],
            0,
            now,
        )
    };
    hit(100);
    assert_eq!(d.instant_pending.lock_ok().get(&9), Some(&100));
    hit(200);
    assert_eq!(d.instant_pending.lock_ok().get(&9), Some(&100));
    // Empty hits early-return even when drops were reported.
    let hints_before = d.instant_hint.lock_ok().len();
    super::instant_arrivals(&d, Vec::new(), 3, 300);
    assert_eq!(d.instant_pending.lock_ok().get(&9), Some(&100));
    assert_eq!(d.instant_hint.lock_ok().len(), hints_before);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------
// sampler_cap_cooldown (TODO 110)
// ---------------------------------------------------------------------

/// The two slots-full shapes cool a sampler down; everything else keeps
/// the retry-next-tick behavior. The Permanent leg is the one that
/// needs the DECLARED cap: eweka is not in the hostname heuristic, so
/// only `max_source_ips` can mark it tight.
#[cfg(feature = "indexer")]
#[test]
fn sampler_cap_cooldown_needs_a_slots_full_refusal_or_a_declared_tight_cap() {
    use nzbkit::nntp::{AuthRefusal, NntpError, classify_auth_refusal};
    let srv = |j: &str| -> nzbkit::config::ServerConfig { serde_json::from_str(j).unwrap() };
    let auth = |line: &str| NntpError::AuthFailed {
        kind: classify_auth_refusal(line),
        line: line.into(),
    };
    let lax = srv(r#"{"host":"news.example.com"}"#);
    let declared = srv(r#"{"host":"news.eweka.example","max_source_ips":2}"#);
    let generous = srv(r#"{"host":"news.eweka.example","max_source_ips":20}"#);

    // A Capacity-classified refusal cools down ANY server: the account
    // is fine and the slots are full, whoever the provider is.
    let cap = auth("502 max number of simultaneous IP addresses reached: 2");
    assert!(matches!(
        cap,
        NntpError::AuthFailed {
            kind: AuthRefusal::Capacity,
            ..
        }
    ));
    assert!(super::sampler_cap_cooldown(&cap, &lax).is_some());
    assert!(super::sampler_cap_cooldown(&cap, &declared).is_some());

    // A Permanent-classified 502 is the address-cap masquerade ONLY on
    // a tight server - declared (eweka is not in the hostname list) or
    // recognised by hostname. On a lax one it stays a credential error.
    let perm = auth("502 Authentication Failed");
    assert!(matches!(
        perm,
        NntpError::AuthFailed {
            kind: AuthRefusal::Permanent,
            ..
        }
    ));
    assert!(super::sampler_cap_cooldown(&perm, &declared).is_some());
    assert!(
        super::sampler_cap_cooldown(&perm, &srv(r#"{"host":"news.tweaknews.example"}"#)).is_some(),
        "the hostname heuristic must keep working without a declared cap"
    );
    assert!(
        super::sampler_cap_cooldown(&perm, &lax).is_none(),
        "a wrong password on a lax server must keep the loud per-tick warn"
    );
    assert!(
        super::sampler_cap_cooldown(&perm, &generous).is_none(),
        "a generous declared allowance is not tight"
    );

    // Network-shaped errors are what the next tick may fix: no cooldown.
    assert!(super::sampler_cap_cooldown(&NntpError::Timeout, &declared).is_none());
    assert!(super::sampler_cap_cooldown(&NntpError::Closed, &declared).is_none());
}

// ---------------------------------------------------------------------
// 12. server_verdict (TODO §154, §156 item 7)
// ---------------------------------------------------------------------

/// The runner's "nothing to dial" gate. Its whole job is to be narrower
/// than "the config did not load": a job held because there is no server
/// waits and starts itself the moment one is added, while a job whose
/// config is unreadable must still reach the download and report the
/// real error rather than sit behind a hold that blames the server list.
///
/// §156 item 7: the last two shapes below are why this reads through
/// `load_no_fallback`. This test USED to end at "a missing config stands
/// the guard down", and whether it passed depended on whether the
/// machine running it had SABnzbd installed - `Config::load` answers a
/// missing file by finding and parsing the host's sabnzbd.ini, so on a
/// box with SAB and no enabled server the verdict came back as this
/// guard's own condition. A test whose verdict moves with what else is
/// installed is not a test, so the ini is written into the fixture here
/// and the guard must ignore it either way.
#[test]
fn no_enabled_servers_is_zero_enabled_and_not_every_config_error() {
    use super::ServerVerdict::{Dialable, NoneEnabled, Unknown};
    let dir = tdir("noservers");
    let write = |name: &str, body: &str| {
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        p
    };
    // The probe also hands back the parsed config for the pick that
    // follows (§H); only the verdict half is under test here.
    let verdict = |p: &std::path::Path| super::server_verdict(p).0;

    // The shape §154 was raised on. `Config::load` reports an EMPTY
    // list as the NoServers error, not as Ok with an empty vec, so a
    // guard written as `is_ok_and(|c| c.servers.is_empty())` would read
    // false here and never fire on the one case that matters.
    assert_eq!(
        verdict(&write("empty.json", r#"{"servers":[]}"#)),
        NoneEnabled
    );

    // The second shape: servers exist, every one is switched off.
    assert_eq!(
        verdict(&write(
            "off.json",
            r#"{"servers":[{"host":"a.example","port":119,"enabled":false},
                       {"host":"b.example","port":119,"enabled":false}]}"#
        )),
        NoneEnabled
    );

    // One enabled server is enough - including when others are off.
    assert_eq!(
        verdict(&write(
            "one.json",
            r#"{"servers":[{"host":"a.example","port":119,"enabled":false},
                       {"host":"b.example","port":119}]}"#
        )),
        Dialable
    );

    // `enabled` defaults to true, which is what an untouched
    // hand-written config looks like.
    assert_eq!(
        verdict(&write(
            "default.json",
            r#"{"servers":[{"host":"a.example","port":119}]}"#
        )),
        Dialable
    );

    // Not our condition: a config that is missing, or that will not
    // parse. Both stand the guard down so the download runs and says
    // what is actually wrong.
    assert_eq!(verdict(&dir.join("nothing-here.json")), Unknown);
    assert_eq!(verdict(&write("torn.json", r#"{"servers":[{"#)), Unknown);

    // §156 item 7, and the reason this fixture writes a sabnzbd.ini:
    // `Config::load`'s missing-file fallback searches next to the
    // config first (issue #15's Docker case), so a SAB ini here is
    // exactly what a typo'd `--config` path finds on a SAB box. An
    // unreadable config stays unreadable whatever that file says -
    // otherwise the guard holds the queue blaming a server list that
    // belongs to another application, in the one case its own doc
    // comment promises to stand down for.
    let sab = dir.join("sabnzbd.ini");
    std::fs::write(&sab, "[servers]\n[[a]]\nhost = news.example\nenable = 1\n").unwrap();
    assert_eq!(verdict(&dir.join("nothing-here.json")), Unknown);
    // The shape that used to publish "no server is configured" for a
    // path nobody could read: SAB installed, no server enabled in it.
    std::fs::write(&sab, "[servers]\n[[a]]\nhost = news.example\nenable = 0\n").unwrap();
    assert_eq!(verdict(&dir.join("nothing-here.json")), Unknown);

    let _ = std::fs::remove_dir_all(&dir);
}

/// The idle trim's log gate (spawn_memory_trim) is a >=64 MB drop of
/// `nzbkit::mem::dashboard_rss()` across `mi_collect(true)`. On macOS
/// that meter must be phys_footprint, NOT ps-style RSS: mimalloc
/// releases pages with MADV_FREE_REUSABLE, which leaves resident_size
/// pinned but drops the footprint immediately. Pin the whole chain
/// here - allocate pipeline-sized buffers under mimalloc (the bin's
/// global allocator, so this lives in the bin test target), free them,
/// force a collection, and require the meter to see the release at the
/// production threshold. If someone swaps the meter back to a naive
/// RSS reading, this fails.
#[cfg(target_os = "macos")]
#[test]
fn trim_meter_sees_madv_free_reusable_release() {
    // 512 MB of anonymous pages, charged by touching, then offered back
    // with the same madvise mimalloc's purge uses. The kernel drops
    // phys_footprint immediately while ps-style resident_size stays
    // pinned until the pages are repurposed - so this passes with a
    // footprint meter and fails with an RSS one. Driving the kernel
    // mechanism directly keeps mimalloc's purge heuristics (which defer
    // under load) out of the assertion; the mi_collect half of the
    // chain is exercised by the daemon's idle trim itself.
    const LEN: usize = 512 << 20;
    let baseline = nzbkit::mem::dashboard_rss().expect("meter");
    // SAFETY: anonymous private mapping; on success the kernel hands us
    // LEN bytes we alone reference, written through valid offsets below,
    // madvised and unmapped with the same pointer and length.
    unsafe {
        let p = libc::mmap(
            std::ptr::null_mut(),
            LEN,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANON | libc::MAP_PRIVATE,
            -1,
            0,
        );
        assert!(p != libc::MAP_FAILED, "mmap failed");
        let bytes = p.cast::<u8>();
        for off in (0..LEN).step_by(4096) {
            bytes.add(off).write(1);
        }
        let while_charged = nzbkit::mem::dashboard_rss().expect("meter");
        let rc = libc::madvise(p, LEN, libc::MADV_FREE_REUSABLE);
        assert_eq!(rc, 0, "madvise(MADV_FREE_REUSABLE) failed");
        let after = nzbkit::mem::dashboard_rss().expect("meter");
        libc::munmap(p, LEN);

        eprintln!(
            "trim meter: baseline={} MB charged={} MB after={} MB",
            baseline >> 20,
            while_charged >> 20,
            after >> 20
        );
        // The meter saw the pages while they were charged...
        assert!(
            while_charged.saturating_sub(baseline) >= 400 << 20,
            "meter never saw the pages: baseline={} MB charged={} MB",
            baseline >> 20,
            while_charged >> 20
        );
        // ...and saw the release at the trim log's 64 MB gate (it drops
        // by the whole 512 MB; the gate is what production tests).
        assert!(
            while_charged.saturating_sub(after) >= 64 << 20,
            "trim log gate would not fire: charged={} MB after={} MB",
            while_charged >> 20,
            after >> 20
        );
    }
}

// ---------------------------------------------------------------------
// index_gate_rendezvous - the runner's bounded wait on the index pass
// gate (the 13 Aug issue-#38 audit's second silent-wedge candidate)
// ---------------------------------------------------------------------

/// The gate's holders all stand down on their own once the runner's
/// job guard is up, so a wait past the bound means a lane is wedged
/// mid-I/O against a mute peer. The old unbounded `gate.lock().await`
/// parked the runner forever in exactly that case, with the job stuck
/// in Downloading and nothing logged. The rendezvous must come back -
/// true when the gate frees (even after a delay), false at the bound.
/// Codex sweep I, 13 Aug 2026: the guard ladder bumped `queue_rev` on a
/// hold's transition edge and stored the hold itself AFTER it. A §129 1b
/// poll landing between the two sees the announcing revision with the
/// old hold, adopts that revision, and - since the store carries no
/// second bump and a held queue has nothing transferring - every
/// matching poll after it omits the queue payload until some unrelated
/// state change moves the revision. The banner is then never drawn.
///
/// `publish_hold` is the fix and this pins it: the store and the bump
/// live in one place, in that order, and no other line in the ladder
/// writes `queue_hold` on a set edge. Source-scanning, like
/// `settings_catalogue` - the ordering is a property of the code, and a
/// runtime test would have to lose the race to notice.
#[test]
fn every_queue_hold_set_edge_goes_through_one_helper() {
    let src = include_str!("tasks/runner.rs");
    let helper = src
        .split_once("fn publish_hold(")
        .expect("the helper exists")
        .1;
    let body = helper.split_once("\n}\n").expect("helper body").0;
    let store = body.find("queue_hold").expect("the helper stores the hold");
    let bump = body
        .find("queue_rev")
        .expect("the helper bumps the revision");
    assert!(
        store < bump,
        "the hold must be stored BEFORE it is announced"
    );

    // Every OTHER `queue_hold` write in the ladder is a clear edge
    // (`= None`); a `Some(` one would be a set edge bypassing the pair.
    let (before, after) = src.split_at(src.find("fn publish_hold(").unwrap());
    let after = after.split_once("\n}\n").expect("helper body").1;
    for (n, line) in before.lines().chain(after.lines()).enumerate() {
        let line = line.trim();
        if !line.contains("queue_hold") || line.starts_with("//") {
            continue;
        }
        assert!(
            !line.contains("Some("),
            "line {n} sets a hold outside publish_hold: {line}"
        );
    }
}

/// Codex sweep H, 13 Aug 2026: the no-servers guard reads the config on
/// the blocking pool under a bound, and the pick that follows then took
/// a SECOND, unbounded `Config::load` on the runner itself - with the
/// job already Downloading and no fetch task yet to cancel. The snapshot
/// the bounded probe already parsed is what feeds the block-account
/// budgets now, so there is no second read to hang in.
///
/// The type signature is most of the assertion: `reset_hub_for_job`
/// takes a config SNAPSHOT and no longer has a path to read. This pins
/// the other half - that the snapshot is really carried, and that a
/// later unreadable config leaves the last good one alone rather than
/// silently dropping every server's budget.
#[tokio::test]
async fn the_server_probe_carries_the_config_the_pick_needs() {
    let dir = tdir("probe-cfg");
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        r#"{"servers":[{"host":"a.example","port":119,"block_bytes":500}]}"#,
    )
    .unwrap();
    let mut probe = super::runner::ServerProbe::default();
    assert!(probe.config().is_none(), "nothing read yet");
    assert_eq!(probe.verdict(&cfg).await, super::ServerVerdict::Dialable);
    let snap = probe.config().expect("the probe kept what it parsed");
    assert_eq!(snap.servers.len(), 1);
    assert_eq!(snap.servers[0].host, "a.example");
    assert_eq!(snap.servers[0].block_bytes, Some(500));

    // Torn file: no verdict, and no news about the server list either.
    std::fs::write(&cfg, r#"{"servers":[{"#).unwrap();
    assert_eq!(probe.verdict(&cfg).await, super::ServerVerdict::Unknown);
    assert_eq!(
        probe.config().map(|c| c.servers.len()),
        Some(1),
        "the last good snapshot survives an unreadable read"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn index_gate_rendezvous_bounds_the_runners_wait() {
    let gate = std::sync::Arc::new(tokio::sync::Mutex::new(()));
    // Free gate: the rendezvous is immediate and clean.
    assert!(super::index_gate_rendezvous(&gate, Duration::from_secs(5)).await);
    // Held gate, standing in for a lane wedged on a black-holed peer:
    // the wait returns false at the bound instead of parking forever.
    // lock_owned so the guard can cross into the release task below.
    let held = gate.clone().lock_owned().await;
    let t0 = Instant::now();
    assert!(!super::index_gate_rendezvous(&gate, Duration::from_millis(50)).await);
    assert!(t0.elapsed() >= Duration::from_millis(50));
    // A holder that releases DURING the wait (a lane's 100 ms
    // preemption poll standing it down) still rendezvouses cleanly.
    let release = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(held);
    });
    assert!(super::index_gate_rendezvous(&gate, Duration::from_secs(5)).await);
    release.await.unwrap();
}

/// Codex sweep 5, M7: the cap gauge is STICKY and the watchdog re-reads
/// it every tick, so banking on every read stamped a fresh date on an
/// old refusal. An idle daemon could turn one Monday event into "capped
/// on 30 of the last 30 days" - which is the sentence a user sends their
/// provider as evidence. One episode banks once.
#[test]
fn a_sticky_cap_gauge_banks_one_episode_once() {
    use crate::serve::tasks::stall::fold_caps_for_test as fold;
    let now_ms_for_test = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    };
    let dir = tdir("capfold");
    let d = super::super::testutil::test_daemon(&dir);
    let servers = vec![(srv("s.example", None), nzbkit::pool::PoolConfig::default())];
    let live = nzbkit::pool::LiveStats::for_servers(&servers);
    live.servers[0].budget.store(100, Ordering::Relaxed);
    live.servers[0].note_cap(38);
    *d.hub.pool_live.lock_ok() = Some(live.clone());

    assert_eq!(fold(&d).len(), 1, "the refusal is banked once");
    assert!(
        fold(&d).is_empty(),
        "and NOT re-banked on the next tick, or an idle daemon invents days"
    );

    // A genuinely new episode - the gauge cleared and capped again - is
    // a new event and must be banked. Stamped explicitly rather than via
    // note_cap: two episodes inside one millisecond would carry the same
    // `since`, and the identity IS the stamp.
    live.servers[0]
        .capped_since
        .store(now_ms_for_test() + 60_000, Ordering::Relaxed);
    assert_eq!(fold(&d).len(), 1, "a second episode is a second event");
}

/// Codex sweep 6, N4: the idle Providers row reads `capped_hosts` and
/// nothing else, so the disproof has to reach the map itself.
///
/// Job 1's refusal at 38 is banked. Job 2 is a fresh pool whose gauge
/// has never recorded a cap - `retire_cap_if_exceeded` returns at its
/// first line for it - and it holds 100 sessions. The fold is the only
/// thing that sees both halves, so it is where the retirement has to
/// happen or the number survives to the next idle poll.
#[test]
fn a_later_job_holding_more_retires_the_banked_ceiling() {
    use crate::serve::tasks::stall::fold_caps_for_test as fold;
    let dir = tdir("capretire");
    let d = super::super::testutil::test_daemon(&dir);
    let servers = vec![(srv("s.example", None), nzbkit::pool::PoolConfig::default())];

    // Job 1: refused while holding 38.
    let job1 = nzbkit::pool::LiveStats::for_servers(&servers);
    job1.servers[0].budget.store(100, Ordering::Relaxed);
    job1.servers[0].note_cap(38);
    *d.hub.pool_live.lock_ok() = Some(job1);
    assert_eq!(fold(&d).len(), 1, "precondition: the ceiling is banked");
    assert_eq!(
        d.capped_hosts
            .lock_ok()
            .get("s.example")
            .map(|c| c.granted_hi),
        Some(38)
    );

    // Job 2: a clean gauge, holding more than that ceiling.
    let job2 = nzbkit::pool::LiveStats::for_servers(&servers);
    job2.servers[0].budget.store(100, Ordering::Relaxed);
    job2.servers[0].connected.store(100, Ordering::Relaxed);
    *d.hub.pool_live.lock_ok() = Some(job2);
    assert!(fold(&d).is_empty(), "nothing new to bank");
    assert!(
        d.capped_hosts.lock_ok().get("s.example").is_none(),
        "and the disproven ceiling is gone, so the idle row cannot show it"
    );
}

/// Codex sweep 6, N8: a job shorter than one watchdog tick could be
/// refused and leave the lifetime ledger empty.
///
/// Banking lived only on the 1-5 s watchdog tick, and the next job
/// replaces `pool_live` outright - so a ~200 ms job that bounced off a
/// capacity limit was never folded at all, and the record a user sends
/// their provider silently missed the day. The runner's own tail is the
/// last moment `pool_live` still points at the job that just ended, so
/// it folds there too. Driven through `settle_job_tail`, the production
/// function, not through the fold helper.
///
/// Codex sweep 7, L2: the REFUSAL LINE rode the same tick and was left
/// behind by that fix, which was cap-ledger-only. The retained pool
/// covers the ordinary case - `pool_live` is not cleared when a job
/// ends, so the idle Providers card still renders the live record and
/// the watchdog copies it within a tick - but a refusal seen only
/// inside a sub-tick job whose pool a later job replaces, or one on the
/// last job before a queue-finished shutdown action ends the process,
/// was never banked at all. Same window, same tail, so the copy folds
/// beside the caps.
#[test]
fn a_job_shorter_than_a_watchdog_tick_still_banks_its_refusal() {
    let dir = tdir("capsubtick");
    let d = super::super::testutil::test_daemon(&dir);
    let servers = vec![(srv("s.example", None), nzbkit::pool::PoolConfig::default())];
    let live = nzbkit::pool::LiveStats::for_servers(&servers);
    live.servers[0].budget.store(100, Ordering::Relaxed);
    live.servers[0].note_cap(38);
    *live.servers[0].refusal.lock_ok() = Some(nzbkit::pool::Refusal {
        permanent: false,
        source_ips: false,
        line: "502 Too many connections".into(),
    });
    *d.hub.pool_live.lock_ok() = Some(live);

    // No watchdog tick ever ran: this is the whole point.
    assert!(
        crate::conntune::load(&d.cfg_path)
            .get("s.example")
            .and_then(|t| t.capped.as_ref())
            .is_none(),
        "precondition: nothing banked yet"
    );

    let mut ledger = None;
    let _ = super::runner::settle_job_tail(&d, "nzo-subtick", &mut ledger);

    let c = crate::conntune::load(&d.cfg_path)
        .get("s.example")
        .and_then(|t| t.capped.clone())
        .expect("the job tail banked the refusal");
    assert_eq!(c.granted_hi, 38);
    assert_eq!(c.days.len(), 1, "one day, one episode");
    let kept = d.last_refusals.lock_ok();
    let r = kept
        .get("s.example")
        .expect("the job tail kept the refusal LINE too");
    assert_eq!(
        r.line, "502 Too many connections",
        "the server's own words are the whole point of keeping it"
    );
    assert!(!r.permanent);
}
