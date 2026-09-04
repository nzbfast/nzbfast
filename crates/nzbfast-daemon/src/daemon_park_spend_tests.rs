//! §290 (Codex F-11): the automatic promotion asks the ceilings.
//!
//! This is the only door of the three that ships ON (`alt_auto_switch`,
//! §282 item 19), and it consulted nothing at all - not the copy cap,
//! not the byte cap, not the metered rule - at the exact moment payload
//! spend begins. With the shipped defaults that is a THIRD copy of one
//! release, started without anybody asking: the original fails, spare A
//! is promoted, A fails, and the repointed spare B goes runnable.
//!
//! Every arm below pins the refusal AND the recovery: a raised ceiling
//! promotes the same spare. A refusal that no setting can lift is a
//! feature that is broken rather than bounded, and it would pass a test
//! that only looked at the first half.

use super::*;

use crate::testutil::test_daemon;

const ORIG: &str = "Some.Show.S01E05.1080p.WEB.H264-AAA";
const ALT_A: &str = "Some.Show.S01E05.720p.HDTV.x264-BBB";
const SPARE_B: &str = "Some.Show.S01E05.2160p.WEB.H265-CCC";
const KEY: &str = "some show/s1e5";

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

/// The three-copy stage: the original and the copy that already
/// replaced it both dead, and a second spare held against the dead
/// replacement. Returns the daemon, the row being parked, and the spare.
fn staged(dir: &Path, servers: &str) -> (Arc<Daemon>, Arc<Mutex<Job>>, Arc<Mutex<Job>>) {
    let d = test_daemon(dir);
    std::fs::write(&d.cfg_path, servers).expect("config");
    let orig = job(
        "orig",
        ORIG,
        serde_json::json!({"state": "Failed", "dupe_key": KEY}),
    );
    let alt_a = job(
        "altA",
        ALT_A,
        serde_json::json!({
            "state": "Failed", "dupe_key": KEY,
            "alt_from": "orig", "alt_from_name": ORIG,
            "fail_message": "verification failed and PAR2 repair could not complete",
        }),
    );
    let spare = job(
        "spareB",
        SPARE_B,
        serde_json::json!({
            "paused": true, "priority": -3, "held_for": "altA",
            "dupe_key": KEY, "total_bytes": 4_000u64,
        }),
    );
    {
        let mut h = d.history.lock_ok();
        h.push(orig);
        h.push(alt_a.clone());
    }
    d.queue.lock_ok().push_back(spare.clone());
    (d, alt_a, spare)
}

/// Is the spare still held, exactly as `altcand::parked_offer_json`
/// needs it to be for §284's click to reach it?
fn still_held(spare: &Arc<Mutex<Job>>) -> bool {
    let g = spare.lock_ok();
    g.paused && g.priority == -3 && g.alt_from.is_empty()
}

const FLAT: &str = r#"{"servers":[{"host":"flat.example","enabled":true}]}"#;
const BLOCK: &str = r#"{"servers":[{"host":"block.example","enabled":true,"block_account":true}]}"#;

/// The copy cap. Two copies of this release have been spent, the
/// ceiling is two, and the spare stays held rather than starting a
/// third.
#[test]
fn the_third_copy_is_refused_and_the_spare_stays_held_for_the_click() {
    let dir = std::env::temp_dir().join(format!("nzbfast-parkspend-cap-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    let (d, alt_a, spare) = staged(&dir, FLAT);
    d.alt.max_copies.store(2, Ordering::Relaxed);

    d.promote_held_alternative(&alt_a, "altA", KEY, Path::new("/tmp/none.nzb"));
    assert!(
        still_held(&spare),
        "the ceiling is spent, so the spare must stay held rather than run"
    );

    // The recovery: the ceiling is the only thing refusing, so raising
    // it promotes the same spare through the same call.
    d.alt.max_copies.store(3, Ordering::Relaxed);
    d.promote_held_alternative(&alt_a, "altA", KEY, Path::new("/tmp/none.nzb"));
    let g = spare.lock_ok();
    assert!(!g.paused && g.priority == 0, "promoted once it fits");
    assert_eq!(g.alt_from, "altA", "and it says what it replaced");
    drop(g);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The byte cap, weighed against the spare's REAL size. The spare is
/// 4,000 bytes and the alternate ceiling is 1,000, so promoting it is
/// over budget however many copies are left.
#[test]
fn a_spare_bigger_than_the_byte_ceiling_is_not_promoted() {
    let dir = std::env::temp_dir().join(format!("nzbfast-parkspend-byte-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    let (d, alt_a, spare) = staged(&dir, FLAT);
    d.alt.max_copies.store(9, Ordering::Relaxed);
    d.alt.max_extra_bytes.store(1_000, Ordering::Relaxed);

    d.promote_held_alternative(&alt_a, "altA", KEY, Path::new("/tmp/none.nzb"));
    assert!(still_held(&spare), "4,000 bytes will not fit under 1,000");

    d.alt.max_extra_bytes.store(9_000, Ordering::Relaxed);
    d.promote_held_alternative(&alt_a, "altA", KEY, Path::new("/tmp/none.nzb"));
    assert!(
        !spare.lock_ok().paused,
        "promoted once the ceiling allows it"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The metered rule, which is the arm `altcand::AltSettings` has
/// documented from the day it was written and which nothing here ever
/// asked: "0 = unlimited ... MUST be consulted before spending a spare
/// on any server marked as a block account, whatever it is set to".
///
/// The answer degrades to §282's documented safe posture rather than
/// disappearing: the spare stays held, so §284's offer on the abandoned
/// row still lets a person start it deliberately.
#[test]
fn unlimited_on_a_block_account_does_not_spend_a_spare_automatically() {
    let dir = std::env::temp_dir().join(format!("nzbfast-parkspend-met-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    let (d, alt_a, spare) = staged(&dir, BLOCK);
    d.alt.max_copies.store(9, Ordering::Relaxed);
    d.alt.max_extra_bytes.store(0, Ordering::Relaxed);

    d.promote_held_alternative(&alt_a, "altA", KEY, Path::new("/tmp/none.nzb"));
    assert!(
        still_held(&spare),
        "nobody agreed to spend paid bytes on a copy they did not pick"
    );

    // A ceiling the user actually SET is a number they chose, and it
    // says how much of the block account this may cost.
    d.alt.max_extra_bytes.store(9_000, Ordering::Relaxed);
    d.promote_held_alternative(&alt_a, "altA", KEY, Path::new("/tmp/none.nzb"));
    assert!(
        !spare.lock_ok().paused,
        "a set ceiling is consent for that many bytes"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The default install still promotes, which is the half a ceiling test
/// can quietly break: `alt_auto_switch` ships ON and `max_copies` ships
/// 2, so the ordinary one-original-one-spare case must go through
/// untouched.
#[test]
fn the_shipped_defaults_still_promote_the_first_spare() {
    let dir = std::env::temp_dir().join(format!("nzbfast-parkspend-def-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    let d = test_daemon(&dir);
    std::fs::write(&d.cfg_path, FLAT).expect("config");
    let orig = job(
        "orig",
        ORIG,
        serde_json::json!({"state": "Failed", "dupe_key": KEY}),
    );
    let spare = job(
        "spareB",
        SPARE_B,
        serde_json::json!({
            "paused": true, "priority": -3, "held_for": "orig",
            "dupe_key": KEY, "total_bytes": 4_000u64,
        }),
    );
    d.history.lock_ok().push(orig.clone());
    d.queue.lock_ok().push_back(spare.clone());

    d.promote_held_alternative(&orig, "orig", KEY, Path::new("/tmp/none.nzb"));
    let g = spare.lock_ok();
    assert!(
        !g.paused && g.priority == 0,
        "the default case is one original and one spare, and it must run"
    );
    assert_eq!(g.alt_from, "orig");
    drop(g);
    let _ = std::fs::remove_dir_all(&dir);
}
