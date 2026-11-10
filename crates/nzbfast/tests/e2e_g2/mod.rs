//! G2 (TODO 358, research/PLAN-WEAVER-PARITY-2026-11-08.md section 2):
//! never report success over packed volumes. A job whose set holds
//! archives either delivers the extracted payload or fails with a named
//! reason - the property Weaver 0.16.12 broke when it reported "job
//! completed" with every RAR volume still packed
//! (research/BENCH-WEAVER-01612-2026-11-07.md section 3b).
//!
//! And item 15 (decision D4 in research/WEAVER-PARITY-PHASE0-2026-11-08.md
//! section 3), which is the CLI half of the same rule: a member OUTSIDE
//! the main payload that stays packed does not fail the job, and is named
//! as not delivered. The daemon half - the history record, and the
//! Completed / Failed word an *arr reads - is `daemon_g2` in the daemon
//! binary.
//!
//! Driven through the real binary and the get tail. The CLI's exit
//! status IS the verdict the daemon files: an engine error is a Failed
//! row, a clean return is a Completed one.
//!
//! A child module so e2e.rs stays inside its size-gate baseline (the
//! e2e_split pattern: harness reached through `super::*`).

use super::*;

/// A real compressed RAR5 with its packed data damaged in the middle:
/// headers intact, so every engine opens it, and the member's CRC fails
/// on the way out - the e2e_vouch fixture, over any of the vendored
/// compression levels.
fn damaged(fixture: &str) -> Vec<u8> {
    let mut arch = std::fs::read(rars_fixture_dir().join(fixture)).unwrap();
    let mid = arch.len() / 2;
    for b in &mut arch[mid..mid + 64] {
        *b ^= 0x5a;
    }
    arch
}

fn good(fixture: &str) -> Vec<u8> {
    std::fs::read(rars_fixture_dir().join(fixture)).unwrap()
}

/// `m1_fastest` (12,582 bytes) is the MAIN payload in the two-set legs.
/// m1, m3 and m5 hold the same `bigtext_64k.bin`, so whichever unpacks
/// delivers that file.
const MAIN: &str = "m1_fastest.rar";
/// `m5_max` (9,922 bytes) is 79% of the main payload: a PEER, not an
/// extra, since the 9 Nov 2026 sweep (review lane 4 item 2). It stands
/// for one episode of a season pack beside another.
const PEER: &str = "m5_max.rar";
/// `filter_e8` (891 bytes) is 7% of the main payload - under the 15%
/// line `rarfix::vouch::is_extra` draws - so it is the sample/extra
/// shape. Until that sweep the extra legs used `m5_max`, which only the
/// old "strictly larger than what unpacked" rule called an extra.
const EXTRA: &str = "filter_e8.rar";

/// The member every compressed fixture above holds.
const MEMBER: &str = "bigtext_64k.bin";

/// The leg runner: the depth-0 chase is OFF so compressed sets demote
/// to the disk ladder, whose "any group produced" rule is the one G2
/// tightens (the e2e_vouch runner, minus the password).
fn run_ladder(fx: &Fixture, srv: &MockServer) -> (String, bool) {
    let cfg = fx.write_config(&[srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    run_get(&cfg, &nzb, &out, &[("NZBFAST_NO_TOP_RAR_CHASE", "1")])
}

/// Any volume of the named stem still in `out`.
fn packed_left(out: &Path, stem: &str) -> bool {
    out.join(format!("{stem}.rar")).exists()
}

/// The happy path, pinned in G2's own words: a store-mode three-volume
/// set with PAR2 completes, the payload is on disk byte for byte, and
/// not one volume is left behind. `clean_store_rar_one_pass` pins the
/// in-stream mechanics; this leg pins the PROPERTY, so a change that
/// kept the mechanics and left a volume packed still reds here.
#[tokio::test(flavor = "multi_thread")]
async fn g2_a_completed_store_set_delivered_its_payload() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (fx, inner, vol_names) = rar_release("g2clean", true);
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let out2 = out.clone();
    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out2, &[]))
        .await
        .unwrap();
    assert!(ok, "a clean store set must complete:\n{log}");
    let got = std::fs::read(out.join("movie.mkv")).expect("a Completed job must deliver movie.mkv");
    assert_eq!(
        got, inner,
        "the delivered payload differs from what was packed"
    );
    for v in &vol_names {
        assert!(
            !out.join(v).exists(),
            "{v} left packed on a Completed job:\n{log}"
        );
    }
}

/// A volume missing from the post with no PAR2 to rebuild it: the set
/// cannot be unpacked, so the job must FAIL, with a reason, and must not
/// deliver a short payload under the release's name.
#[tokio::test(flavor = "multi_thread")]
async fn g2_a_missing_volume_past_par2_fails_with_a_reason() {
    let mut fx = Fixture::new("g2missing");
    let inner = payload(900_000, 7);
    let vols = fixtures::rar5_volume_set(&[
        &[("movie.mkv", 900_000, &inner[..350_001], false, true)],
        &[("movie.mkv", 900_000, &inner[350_001..700_001], true, true)],
        &[("movie.mkv", 900_000, &inner[700_001..], true, false)],
    ]);
    // part2 is never posted, and there is no recovery set.
    fx.add_file("r.part1.rar", &vols[0], 60_000);
    fx.add_file("r.part3.rar", &vols[2], 60_000);
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let (log, ok, whole) = tokio::task::spawn_blocking(move || {
        let cfg = fx.write_config(&[&srv]);
        let nzb = fx.write_nzb();
        let out = fx.dir.join("out");
        let (log, ok) = run_get(&cfg, &nzb, &out, &[]);
        let whole = std::fs::read(out.join("movie.mkv")).is_ok_and(|g| g == inner);
        (log, ok, whole)
    })
    .await
    .unwrap();
    assert!(!ok, "a set missing a volume must not complete:\n{log}");
    assert!(
        log.contains("could not be") || log.contains("missing") || log.contains("incomplete"),
        "the failure must name a reason:\n{log}"
    );
    assert!(
        !whole,
        "impossible: the payload rebuilt without part2:\n{log}"
    );
}

/// A lone archive that cannot be unpacked (headers fine, data damaged,
/// no PAR2): Failed with the unpack sentence, never Completed over the
/// packed volume.
#[tokio::test(flavor = "multi_thread")]
async fn g2_a_broken_lone_archive_fails_with_a_reason() {
    let mut fx = Fixture::new("g2broken");
    fx.add_file("main.rar", &damaged(MAIN), 1500);
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let (log, ok, left) = tokio::task::spawn_blocking(move || {
        let (log, ok) = run_ladder(&fx, &srv);
        (log, ok, packed_left(&fx.dir.join("out"), "main"))
    })
    .await
    .unwrap();
    assert!(!ok, "a broken lone archive must fail the job:\n{log}");
    assert!(
        log.contains("could not be unpacked"),
        "the failure must say the archive could not be unpacked:\n{log}"
    );
    assert!(left, "the volume is kept for the retry:\n{log}");
}

/// THE G2 FIX. The main payload is damaged and a smaller sample beside
/// it unpacks, with no PAR2 in the post. Before G2 the ladder's "any
/// group produced" rule completed this job green with the release still
/// packed and only the sample delivered - Weaver's failure, here - and
/// only a warning line said so. Now the leftover outweighs everything
/// that unpacked, so it is the main payload and the job fails naming it.
#[tokio::test(flavor = "multi_thread")]
async fn g2_a_packed_main_payload_beside_an_unpacked_sample_fails() {
    let mut fx = Fixture::new("g2main");
    fx.add_file("main.rar", &damaged(MAIN), 1500);
    fx.add_file("sample.rar", &good(PEER), 1500);
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let (log, ok, left) = tokio::task::spawn_blocking(move || {
        let (log, ok) = run_ladder(&fx, &srv);
        (log, ok, packed_left(&fx.dir.join("out"), "main"))
    })
    .await
    .unwrap();
    assert!(
        !ok,
        "a job whose main payload stayed packed must fail, whatever unpacked beside it:\n{log}"
    );
    assert!(
        log.contains("the main payload could not be unpacked: main is still packed"),
        "the failure must name the main payload:\n{log}"
    );
    assert!(
        left,
        "the main payload's volume is kept for the retry:\n{log}"
    );
}

/// Item 15 (D4): the mirror image. A good main payload beside a broken
/// extra completes - the release landed - and the extra is named as not
/// delivered, on a line of its own rather than only inside the generic
/// leftovers warning.
#[tokio::test(flavor = "multi_thread")]
async fn item15_a_broken_extra_beside_a_good_main_completes_and_is_named() {
    let mut fx = Fixture::new("i15extra");
    fx.add_file("main.rar", &good(MAIN), 1500);
    fx.add_file("sample.rar", &damaged(EXTRA), 1500);
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let (log, ok, delivered, left) = tokio::task::spawn_blocking(move || {
        let (log, ok) = run_ladder(&fx, &srv);
        let out = fx.dir.join("out");
        (
            log,
            ok,
            out.join(MEMBER).exists(),
            packed_left(&out, "sample"),
        )
    })
    .await
    .unwrap();
    assert!(
        ok,
        "a broken extra must not fail a job whose main payload landed:\n{log}"
    );
    assert!(delivered, "the main payload must be on disk:\n{log}");
    assert!(
        log.contains("not delivered (outside the main payload, left packed): sample"),
        "the extra must be named as not delivered:\n{log}"
    );
    assert!(left, "the extra stays on disk to unpack by hand:\n{log}");
    assert!(
        !log.contains("the main payload could not be unpacked"),
        "{log}"
    );
}

/// Review lane 4 item 2 (9 Nov 2026): a set that failed beside one that
/// unpacked, at 79% of its size, with no PAR2 to say which is the
/// release. "Strictly larger than what unpacked" completed this - a
/// season pack with an episode missing - and now it fails naming it.
#[tokio::test(flavor = "multi_thread")]
async fn g2_a_failed_peer_set_beside_a_delivered_one_fails() {
    let mut fx = Fixture::new("g2peer");
    fx.add_file("e03.rar", &good(MAIN), 1500);
    fx.add_file("e05.rar", &damaged(PEER), 1500);
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let (log, ok, left) = tokio::task::spawn_blocking(move || {
        let (log, ok) = run_ladder(&fx, &srv);
        (log, ok, packed_left(&fx.dir.join("out"), "e05"))
    })
    .await
    .unwrap();
    assert!(
        !ok,
        "a failed set the size of one that unpacked is part of the main payload:\n{log}"
    );
    assert!(
        log.contains("the main payload could not be unpacked: e05 is still packed"),
        "the failure must name the failed peer:\n{log}"
    );
    assert!(left, "the failed set is kept for the retry:\n{log}");
}

/// Item 5, decision D4's extension (9 Nov 2026): a broken extra the job's OWN
/// PAR2 set vouches for no longer fails a job whose main payload landed.
/// Before, TODO 164's "a vouched set stayed packed" outranked everything
/// and this exited 1 with the release delivered.
#[tokio::test(flavor = "multi_thread")]
async fn item15_a_par2_vouched_broken_extra_completes_and_is_named() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("i15vouched");
    fx.add_file("main.rar", &good(MAIN), 1500);
    fx.add_file("sample.rar", &damaged(EXTRA), 1500);
    assert!(
        fx.add_par2(20, &["main.rar", "sample.rar"], 1500),
        "par2 create failed"
    );
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let (log, ok, delivered, left) = tokio::task::spawn_blocking(move || {
        let (log, ok) = run_ladder(&fx, &srv);
        let out = fx.dir.join("out");
        (
            log,
            ok,
            out.join(MEMBER).exists(),
            packed_left(&out, "sample"),
        )
    })
    .await
    .unwrap();
    assert!(
        ok,
        "a vouched broken extra must not fail a job whose main payload landed:\n{log}"
    );
    assert!(delivered, "the main payload must be on disk:\n{log}");
    assert!(
        log.contains("not delivered (outside the main payload, left packed): sample"),
        "the extra must be named as not delivered:\n{log}"
    );
    assert!(left, "the extra stays on disk:\n{log}");
    assert!(!log.contains("the PAR2 set vouches for"), "{log}");
}
