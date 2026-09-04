//! §290 (Codex F-09/F-11): what the derived ledger counts, and what the
//! admission does with it.
//!
//! Each test here is one of the three holes the module header names, and
//! each was verified to FAIL against the arithmetic it replaces - a
//! spend read off `downloaded_bytes` alone, a copy count read off the
//! §96.3 breaker alone, and a size taken from the indexer's own
//! advertisement. A ceiling test that passes either way is a ceiling
//! nobody is holding.

use super::*;

use crate::testutil::{flat_rate_config, test_daemon};

fn tdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "nzbfast-altspend-{tag}-{}-{}",
        std::process::id(),
        tag.len()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("temp dir");
    d
}

/// One episode, so every row below counts against one target.
const ORIG: &str = "Some.Show.S01E05.1080p.WEB.H264-AAA";
const ALT_A: &str = "Some.Show.S01E05.720p.HDTV.x264-BBB";
const ALT_B: &str = "Some.Show.S01E05.2160p.WEB.H265-CCC";

pub fn job(id: &str, name: &str, extra: serde_json::Value) -> Arc<Mutex<Job>> {
    let mut v = serde_json::json!({
        "nzo_id": id, "name": name, "nzb_path": "/tmp/x.nzb",
        "out_dir": format!("/tmp/out/{id}"), "state": "Queued",
    });
    if let Some(m) = extra.as_object() {
        for (k, val) in m {
            v[k] = val.clone();
        }
    }
    Arc::new(Mutex::new(job_from_json(&v).expect("job_from_json")))
}

fn ctx_for(d: &Daemon, id: &str, name: &str) -> super::AltCtx {
    d.alt_ctx(
        id,
        name,
        crate::giveup::target_keys(&crate::wall::parse_release(name)),
    )
}

/// **F-09's first hole.** A hunted row that has downloaded nothing yet
/// committed NOTHING to the old accounting, which read
/// `Job::downloaded_bytes` off the queue. So the moment after one copy
/// was admitted was the moment the ceiling was widest, which is exactly
/// when the second request arrives.
///
/// The figures are chosen so the two readings disagree: 5 GB committed
/// against 0 GB downloaded, under a 6 GB ceiling.
#[test]
fn a_live_alternate_commits_its_whole_size_before_it_has_fetched_a_byte() {
    let dir = tdir("live");
    let d = test_daemon(&dir);
    flat_rate_config(&d);
    d.alt
        .max_extra_bytes
        .store(6_000_000_000, Ordering::Relaxed);
    d.alt.max_copies.store(9, Ordering::Relaxed);
    d.history.lock_ok().push(job(
        "orig",
        ORIG,
        serde_json::json!({"state": "Failed", "downloaded_bytes": 1_000_000_000u64}),
    ));
    d.queue.lock_ok().push_back(job(
        "alt1",
        ALT_A,
        serde_json::json!({
            "alt_from": "orig", "alt_from_name": ORIG,
            "total_bytes": 5_000_000_000u64, "downloaded_bytes": 0u64,
        }),
    ));

    let ctx = ctx_for(&d, "orig", ORIG);
    let (_, bytes) = d.alt_committed(&ctx);
    assert_eq!(
        bytes, 5_000_000_000,
        "the live alternate commits its full size, not its progress"
    );
    // The ORIGINAL's own gigabyte is not in it: `max_extra_bytes` is
    // what an alternate may add ON TOP of the original grab.
    assert!(
        bytes < 5_500_000_000,
        "the original grab must not be charged to the alternate ceiling"
    );
    assert_eq!(
        d.alt_admit(&ctx, 2_000_000_000, super::Trigger::Clicked),
        Err(super::NoHunt::ByteCap),
        "1 GB of ceiling is left, so a 2 GB copy is refused"
    );
    assert_eq!(
        d.alt_admit(&ctx, 500_000_000, super::Trigger::Clicked),
        Ok(()),
        "...and one that fits is admitted"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// **F-09's race, as the copy cap sees it.** Two requests for one dead
/// target, the first already published and downloading nothing. The old
/// count came off the §96.3 breaker's failed-stem list alone, so the
/// live copy was invisible and both requests passed a ceiling of 2.
#[test]
fn a_second_admission_cannot_pass_the_cap_while_the_first_sits_at_zero() {
    let dir = tdir("race");
    let d = test_daemon(&dir);
    flat_rate_config(&d);
    d.alt.max_copies.store(2, Ordering::Relaxed);
    d.history
        .lock_ok()
        .push(job("orig", ORIG, serde_json::json!({"state": "Failed"})));

    let ctx = ctx_for(&d, "orig", ORIG);
    assert_eq!(
        d.alt_admit(&ctx, 1000, super::Trigger::Auto),
        Ok(()),
        "the first replacement is inside a ceiling of 2"
    );
    // ...which publishes, at zero progress.
    d.queue.lock_ok().push_back(job(
        "alt1",
        ALT_A,
        serde_json::json!({
            "alt_from": "orig", "alt_from_name": ORIG,
            "total_bytes": 4_000u64, "downloaded_bytes": 0u64,
        }),
    ));
    assert_eq!(
        d.alt_admit(&ctx, 1000, super::Trigger::Auto),
        Err(super::NoHunt::CopyCap(2)),
        "the second must see the first, published or not yet downloading"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// **The release, and it is the reason there is no ledger.** A
/// reservation that leaks is a cap that tightens by itself over uptime,
/// so the commitment is derived from the stores that already forget a
/// cancelled row. Three terminal shapes, all of them free.
#[test]
fn a_cancelled_or_finished_copy_hands_its_reservation_back() {
    let dir = tdir("release");
    let d = test_daemon(&dir);
    flat_rate_config(&d);
    d.alt.max_copies.store(9, Ordering::Relaxed);
    d.alt.max_extra_bytes.store(10_000, Ordering::Relaxed);
    d.history
        .lock_ok()
        .push(job("orig", ORIG, serde_json::json!({"state": "Failed"})));
    let live = job(
        "alt1",
        ALT_A,
        serde_json::json!({
            "alt_from": "orig", "alt_from_name": ORIG,
            "total_bytes": 8_000u64, "downloaded_bytes": 1_000u64,
        }),
    );
    d.queue.lock_ok().push_back(live.clone());
    let ctx = ctx_for(&d, "orig", ORIG);
    assert_eq!(d.alt_committed(&ctx).1, 8_000, "live: the whole size");

    // 1. The user's delete lands mid flight. The bytes already fetched
    //    are spent; the ones this row will now never fetch are not.
    live.lock_ok().tombstone = true;
    assert_eq!(
        d.alt_committed(&ctx).1,
        1_000,
        "a tombstoned row releases the bytes it will not spend"
    );

    // 2. It parks into history, terminal, and settles at what it really
    //    cost.
    live.lock_ok().tombstone = false;
    d.queue.lock_ok().clear();
    d.history.lock_ok().push(live.clone());
    assert_eq!(
        d.alt_committed(&ctx).1,
        1_000,
        "a terminal row is charged what it downloaded, not what it planned"
    );

    // 3. The record is deleted outright, which is the path no ledger
    //    release hook would ever be called on.
    d.history.lock_ok().retain(|j| j.lock_ok().nzo_id != "alt1");
    assert_eq!(
        d.alt_committed(&ctx).1,
        0,
        "a deleted record cannot hold a reservation open"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// **F-11's third copy.** The chain is walked BOTH ways, so an
/// alternate that is itself replacing an alternate does not reset the
/// budget at every hop. Original, spare A promoted, A failed: the
/// question B's promotion asks is about A, and the answer has to
/// include the original A replaced.
#[test]
fn the_chain_is_counted_end_to_end_so_a_third_copy_is_over_a_ceiling_of_two() {
    let dir = tdir("chain");
    let d = test_daemon(&dir);
    flat_rate_config(&d);
    d.alt.max_copies.store(2, Ordering::Relaxed);
    {
        let mut h = d.history.lock_ok();
        h.push(job("orig", ORIG, serde_json::json!({"state": "Failed"})));
        h.push(job(
            "altA",
            ALT_A,
            serde_json::json!({
                "state": "Failed", "alt_from": "orig", "alt_from_name": ORIG,
            }),
        ));
    }
    // The question `promote_held_alternative` asks when A dies.
    let ctx = ctx_for(&d, "altA", ALT_A);
    assert_eq!(
        d.alt_committed(&ctx).0,
        2,
        "the original and the copy that replaced it are two copies"
    );
    assert_eq!(
        d.alt_admit(&ctx, 1000, super::Trigger::Auto),
        Err(super::NoHunt::CopyCap(2)),
        "so a third is over a ceiling of two"
    );
    // Raise the ceiling and the same spare is admitted: the refusal is
    // the SETTING biting, not the walk refusing everything.
    d.alt.max_copies.store(3, Ordering::Relaxed);
    assert_eq!(d.alt_admit(&ctx, 1000, super::Trigger::Auto), Ok(()));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A copy of one release retried is one copy, not two: the stems are
/// distinct names and the count is over the set. Same rule
/// `giveup::record_failure` applies to its own evidence, and it has to
/// be the same or a target that fails twice reads as spent twice.
#[test]
fn one_release_tried_twice_is_still_one_copy() {
    let dir = tdir("stems");
    let d = test_daemon(&dir);
    flat_rate_config(&d);
    d.alt.max_copies.store(2, Ordering::Relaxed);
    {
        let mut h = d.history.lock_ok();
        h.push(job("orig", ORIG, serde_json::json!({"state": "Failed"})));
        // The SAME release name, fetched again through the mechanism.
        h.push(job(
            "again",
            ORIG,
            serde_json::json!({
                "state": "Failed", "alt_from": "orig", "alt_from_name": ORIG,
            }),
        ));
    }
    let ctx = ctx_for(&d, "orig", ORIG);
    assert_eq!(d.alt_committed(&ctx).0, 1, "one release, one copy");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The §96.3 breaker's stems still count, which is what carries the
/// evidence across a restart and past history retention. This is the
/// hunt's shipped copy accounting, kept rather than replaced.
#[test]
fn the_breakers_own_failed_stems_still_count_as_copies() {
    let dir = tdir("giveup");
    let d = test_daemon(&dir);
    flat_rate_config(&d);
    d.alt.max_copies.store(2, Ordering::Relaxed);
    let keys = crate::giveup::target_keys(&crate::wall::parse_release(ORIG));
    {
        let mut st = d.giveup.lock_ok();
        st.record_failure(&keys, ALT_A, unix_now());
        st.record_failure(&keys, ALT_B, unix_now());
    }
    let ctx = ctx_for(&d, "orig", ORIG);
    assert!(
        d.alt_committed(&ctx).0 >= 2,
        "two buried releases plus the original are past a ceiling of two"
    );
    assert_eq!(
        d.alt_admit(&ctx, 1000, super::Trigger::Auto),
        Err(super::NoHunt::CopyCap(3))
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The metered rule reaches the AUTOMATIC road and stands down on the
/// clicked one, which is `hunt::Trigger`'s whole contract - and it now
/// governs the promotion door too. `altcand::AltSettings` has always
/// said `alt_max_extra_bytes` "MUST be consulted before spending a
/// spare on any server marked as a block account, whatever it is set
/// to"; until §290 the one door that ships ON never asked.
#[test]
fn unlimited_is_refused_on_a_block_account_only_when_nobody_clicked() {
    let dir = tdir("metered");
    let d = test_daemon(&dir);
    std::fs::write(
        &d.cfg_path,
        r#"{"servers":[{"host":"block.example","enabled":true,"block_account":true}]}"#,
    )
    .expect("config");
    d.alt.max_copies.store(9, Ordering::Relaxed);
    d.alt.max_extra_bytes.store(0, Ordering::Relaxed);
    d.history
        .lock_ok()
        .push(job("orig", ORIG, serde_json::json!({"state": "Failed"})));
    let ctx = ctx_for(&d, "orig", ORIG);
    assert_eq!(
        d.alt_admit(&ctx, 1000, super::Trigger::Auto),
        Err(super::NoHunt::MeteredNoBudget),
        "the daemon may not spend paid bytes on a copy nobody picked"
    );
    assert_eq!(
        d.alt_admit(&ctx, 1000, super::Trigger::Clicked),
        Ok(()),
        "a person clicking is the consent the guard stands in for"
    );
    // A ceiling the user actually SET is a number they chose, so it
    // still applies on both roads.
    d.alt.max_extra_bytes.store(500, Ordering::Relaxed);
    assert_eq!(
        d.alt_admit(&ctx, 1000, super::Trigger::Clicked),
        Err(super::NoHunt::ByteCap)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A HELD SPARE spends nothing, and must not be charged for anything: a
/// spare is an NZB file and never a byte of payload, which is the whole
/// reason holding two of them is affordable. It joins the ledger the
/// moment something promotes it, which is when `alt_from` is stamped.
#[test]
fn a_held_spare_reserves_nothing_until_it_is_promoted() {
    let dir = tdir("held");
    let d = test_daemon(&dir);
    flat_rate_config(&d);
    d.alt.max_copies.store(2, Ordering::Relaxed);
    d.alt.max_extra_bytes.store(10_000, Ordering::Relaxed);
    d.history
        .lock_ok()
        .push(job("orig", ORIG, serde_json::json!({"state": "Failed"})));
    let spare = job(
        "spare",
        ALT_A,
        serde_json::json!({
            "paused": true, "priority": -3, "held_for": "orig",
            "total_bytes": 9_000u64,
        }),
    );
    d.queue.lock_ok().push_back(spare.clone());
    let ctx = ctx_for(&d, "orig", ORIG);
    assert_eq!(
        d.alt_committed(&ctx),
        (1, 0),
        "one copy spent (the original), no bytes committed by a held NZB"
    );
    assert_eq!(d.alt_admit(&ctx, 9_000, super::Trigger::Auto), Ok(()));
    // Promoted: `alt_from` is what every door stamps, and it is what
    // puts the row on the ledger.
    {
        let mut g = spare.lock_ok();
        g.paused = false;
        g.priority = 0;
        g.alt_from = "orig".into();
        g.alt_from_name = ORIG.into();
    }
    assert_eq!(d.alt_committed(&ctx), (2, 9_000));
    let _ = std::fs::remove_dir_all(&dir);
}
