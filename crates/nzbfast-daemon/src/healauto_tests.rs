//! §310's scheduled heal. Each test is one of the rules the automatic
//! road is made of, and every one of them is a rule the CLICKED road
//! does not have:
//!
//! * it is OFF, and a sweep with the switch off does nothing at all;
//! * it never spends on a target it would have to SEARCH for, because
//!   nobody is there to judge a different post of the release;
//! * its byte ceiling is charged the WHOLE post, not the damaged
//!   remainder, so it holds even if the remainder-only property does
//!   not - `tests/daemon_heal/`'s leg A, which landed the same day,
//!   measured that worst case at 32 bodies against 31 for an ordinary
//!   download, so the whole-post charge is if anything slightly low;
//! * it stands down for a download rather than reading the library out
//!   from under one;
//! * the walk finds a manifest folder and nothing else.

use super::*;
use crate::manifest::Manifest;
use crate::testutil::test_daemon;
use nzbkit::par2::{BlockCheck, Par2File, Par2Set};

fn tdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "nzbfast-healauto-{tag}-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("t").len()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("temp dir");
    d
}

fn body(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

fn md5_of(b: &[u8]) -> [u8; 16] {
    use md5::{Digest, Md5};
    let mut h = Md5::new();
    h.update(b);
    h.finalize().into()
}

/// A real `Par2Set` over generated payload. Same shape as
/// `heal_tests::set_over`, which is private to that module.
fn set_over(files: &[(&str, &[u8])], bs: usize) -> Par2Set {
    let files = files
        .iter()
        .map(|(name, data)| {
            let blocks = data
                .chunks(bs)
                .map(|c| {
                    let mut padded = c.to_vec();
                    padded.resize(bs, 0);
                    let mut crc = crc32fast::Hasher::new();
                    crc.update(&padded);
                    BlockCheck {
                        md5: md5_of(&padded),
                        crc32: crc.finalize(),
                    }
                })
                .collect();
            Par2File {
                file_id: [0u8; 16],
                name: (*name).to_string(),
                length: data.len() as u64,
                md5: md5_of(data),
                md5_16k: md5_of(&data[..data.len().min(16384)]),
                blocks,
            }
        })
        .collect();
    Par2Set {
        recovery_set_id: [0u8; 16],
        block_size: bs as u64,
        files,
        nonrecovery: Vec::new(),
        recovery_blocks_seen: 0,
    }
}

fn settle(dir: &Path, job: &str, sha: &str, files: &[(&str, Vec<u8>)]) {
    for (n, d) in files {
        std::fs::write(dir.join(n), d).expect("payload");
    }
    let refs: Vec<(&str, &[u8])> = files.iter().map(|(n, d)| (*n, d.as_slice())).collect();
    let set = set_over(&refs, 4096);
    Manifest::from_set(&set, job, sha, false)
        .write_reconciled(dir)
        .expect("manifest");
}

fn damage(dir: &Path, name: &str) {
    let p = dir.join(name);
    let mut b = std::fs::read(&p).expect("read back");
    let at = b.len() / 2;
    b[at] ^= 0x40;
    std::fs::write(&p, b).expect("damage");
}

const EP1: &str = "Show.S01E01.1080p.WEB-DL.x264-GRP";

/// Stand a history record up for a settled post, with its spooled .nzb
/// on disk and a size on the row, and hand back the sha the manifest
/// must carry to match it.
fn record_post(d: &Daemon, dir: &Path, id: &str, name: &str, total_bytes: u64) -> String {
    let nzb = dir.join(format!("{id}.nzb"));
    let xml = format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\
         <file poster=\"x\" date=\"1700000000\" subject=\"&quot;{id}.bin&quot; yEnc (1/1)\">\
         <groups><group>g</group></groups><segments>\
         <segment bytes=\"1000\" number=\"1\">{id}@e</segment></segments></file></nzb>"
    );
    std::fs::write(&nzb, &xml).expect("spool nzb");
    let sha = super::job::nzb_sha(xml.as_bytes());
    d.history.lock_ok().push(Arc::new(Mutex::new(
        super::job::job_from_json(&serde_json::json!({
            "nzo_id": id, "name": name, "origin": "dashboard",
            "state": "Completed",
            "out_dir": dir.to_string_lossy(),
            "nzb_path": nzb.to_string_lossy(),
            "nzb_sha": sha,
            "total_bytes": total_bytes,
        }))
        .expect("history row"),
    )));
    sha
}

/// A damaged library folder with a recorded post behind it, ready to
/// sweep. Returns the daemon, the library folder and the list the sweep
/// walks.
fn rig(tag: &str, total_bytes: u64) -> (Arc<Daemon>, PathBuf, Vec<PathBuf>) {
    let dir = tdir(tag);
    let d = test_daemon(&dir);
    let lib = dir.join("library");
    std::fs::create_dir_all(&lib).expect("library");
    let sha = record_post(&d, &dir, "nzo-ep1", EP1, total_bytes);
    settle(&lib, EP1, &sha, &[("Show - S01E01.mkv", body(20_000, 1))]);
    damage(&lib, "Show - S01E01.mkv");
    let dirs = manifest_dirs(&lib);
    (d, lib, dirs)
}

fn heal_rows(d: &Daemon) -> usize {
    d.queue
        .lock_ok()
        .iter()
        .filter(|j| j.lock_ok().origin.starts_with("heal:"))
        .count()
}

/// THE DEFAULT, and the one this feature is judged on. A daemon nobody
/// has switched this on for sweeps nothing, whatever it would have
/// found - and it says which reason, because a background pass that has
/// quietly stopped is otherwise a mystery.
#[test]
fn the_sweep_is_off_by_default() {
    let (d, lib, dirs) = rig("off", 5_000_000_000);
    assert!(
        !d.heal_auto.enabled.load(Ordering::Relaxed),
        "§310's scheduled heal ships OFF"
    );
    assert_eq!(
        crate::healauto::heal_auto_standdown(&d),
        Some("the switch is off")
    );
    let out = crate::healauto::heal_auto_sweep(&d, &dirs, None);
    assert_eq!(out, SweepOutcome::default(), "nothing read, nothing spent");
    assert_eq!(heal_rows(&d), 0);
    let _ = std::fs::remove_dir_all(lib.parent().expect("parent"));
}

/// Switched on, the same folder IS repaired, and the repair is the
/// ordinary one: it carries the library folder as its donor, which is
/// what makes it cheap rather than a second full download.
#[test]
fn switched_on_it_repairs_the_recorded_post_with_the_folder_as_donor() {
    let (d, lib, dirs) = rig("on", 5_000_000_000);
    d.heal_auto.enabled.store(true, Ordering::Relaxed);

    let out = crate::healauto::heal_auto_sweep(&d, &dirs, None);
    assert_eq!(out.verified, 1, "{out:?}");
    assert_eq!(out.damaged, 1, "{out:?}");
    assert_eq!(out.started, 1, "{out:?}");
    assert!(out.refused.is_empty(), "{out:?}");

    let row = {
        let q = d.queue.lock_ok();
        q.iter()
            .map(|j| j.lock_ok())
            .find(|g| g.origin.starts_with("heal:"))
            .map(|g| (g.heal_dir.clone(), g.paused, g.name.clone()))
            .expect("a heal row on the queue")
    };
    assert_eq!(row.0, lib, "the damaged folder rides along as the donor");
    assert!(!row.1, "released once the donor is stamped");
    assert_eq!(row.2, EP1);
    let _ = std::fs::remove_dir_all(lib.parent().expect("parent"));
}

/// RULE 2, and it has no equivalent on the clicked road. With no
/// recorded post the manual heal falls through to an indexer search,
/// which spends a grab and can return a DIFFERENT post of the release.
/// A person reading the damage report can judge that; a sweep cannot,
/// so it declines and leaves the target where the click can still find
/// it.
#[test]
fn a_target_that_would_need_a_search_is_left_for_the_manual_road() {
    let dir = tdir("search");
    let d = test_daemon(&dir);
    d.heal_auto.enabled.store(true, Ordering::Relaxed);
    let lib = dir.join("library");
    std::fs::create_dir_all(&lib).expect("library");
    // Settled against a post NOTHING has on record: no history row, no
    // spooled .nzb.
    settle(
        &lib,
        EP1,
        "sha-not-on-record",
        &[("Show - S01E01.mkv", body(20_000, 1))],
    );
    damage(&lib, "Show - S01E01.mkv");

    let out = crate::healauto::heal_auto_sweep(&d, &manifest_dirs(&lib), None);
    assert_eq!(out.damaged, 1, "the damage IS seen: {out:?}");
    assert_eq!(out.started, 0, "and nothing is spent on it: {out:?}");
    assert_eq!(out.refused, vec![(AutoRefusal::NotRecorded, 1)]);
    assert_eq!(heal_rows(&d), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

/// THE LOAD-BEARING CEILING. The post is 30 GB and the sweep may spend
/// 20 GB, so nothing starts - even though the DAMAGE is one flipped
/// byte and a heal that behaves as advertised would re-fetch a few
/// blocks. That is the point: nothing in this tree had MEASURED that a
/// heal fetches only the remainder when this was written, so the
/// ceiling is charged the whole post. `tests/daemon_heal/` has since
/// measured it, and leg A - nothing donatable - came to 32 bodies
/// against the 31 an ordinary download of the same post costs, which is
/// exactly what the whole-post charge is for. A lane that makes this
/// test pass by charging a measured remainder owes the full-post
/// fallback and the argument for it in `healauto.rs`'s header.
#[test]
fn the_byte_ceiling_is_charged_the_whole_post_not_the_damage() {
    let (d, lib, dirs) = rig("bytes", 30_000_000_000);
    d.heal_auto.enabled.store(true, Ordering::Relaxed);
    assert_eq!(
        d.heal_auto.max_bytes.load(Ordering::Relaxed),
        20_000_000_000,
        "the shipped ceiling this test is written against"
    );

    let out = crate::healauto::heal_auto_sweep(&d, &dirs, None);
    assert_eq!(out.damaged, 1, "{out:?}");
    assert_eq!(out.started, 0, "{out:?}");
    assert_eq!(out.refused, vec![(AutoRefusal::ByteBudget, 1)]);
    assert_eq!(heal_rows(&d), 0);

    // ...and the SAME folder, with room for the post, is repaired. The
    // control arm: without it this test passes just as well on a sweep
    // that never repairs anything.
    d.heal_auto
        .max_bytes
        .store(40_000_000_000, Ordering::Relaxed);
    let again = crate::healauto::heal_auto_sweep(&d, &dirs, None);
    assert_eq!(again.started, 1, "{again:?}");
    let _ = std::fs::remove_dir_all(lib.parent().expect("parent"));
}

/// A record with no size on it is not a licence to spend an unknown
/// amount: the automatic road never spends what it cannot count.
#[test]
fn a_post_of_unknown_size_is_never_spent_on() {
    let (d, lib, dirs) = rig("nosize", 0);
    d.heal_auto.enabled.store(true, Ordering::Relaxed);
    let out = crate::healauto::heal_auto_sweep(&d, &dirs, None);
    assert_eq!(out.damaged, 1, "{out:?}");
    assert_eq!(out.refused, vec![(AutoRefusal::SizeUnknown, 1)]);
    assert_eq!(heal_rows(&d), 0);
    let _ = std::fs::remove_dir_all(lib.parent().expect("parent"));
}

/// A verify is a FULL READ of every covered file, on the same disk the
/// download is using, so a queued job stops the sweep before it opens
/// anything.
#[test]
fn a_waiting_download_stops_the_sweep_before_it_reads() {
    let (d, lib, dirs) = rig("busy", 5_000_000_000);
    d.heal_auto.enabled.store(true, Ordering::Relaxed);
    d.queue.lock_ok().push_back(Arc::new(Mutex::new(
        super::job::job_from_json(&serde_json::json!({
            "nzo_id": "waiting", "name": "Something.Else", "state": "Queued",
            "nzb_path": lib.join("waiting.nzb").to_string_lossy(),
            "out_dir": lib.to_string_lossy(),
        }))
        .expect("queued row"),
    )));
    assert_eq!(
        crate::healauto::heal_auto_standdown(&d),
        Some("a download is waiting")
    );

    let out = crate::healauto::heal_auto_sweep(&d, &dirs, None);
    assert_eq!(out.verified, 0, "not one folder was read: {out:?}");
    assert_eq!(out.started, 0, "{out:?}");
    assert_eq!(heal_rows(&d), 0);
    let _ = std::fs::remove_dir_all(lib.parent().expect("parent"));
}

/// Offline is a promise that this machine is touching no provider, and a
/// repair is a download.
#[test]
fn offline_stands_the_sweep_down() {
    let (d, lib, dirs) = rig("offline", 5_000_000_000);
    d.heal_auto.enabled.store(true, Ordering::Relaxed);
    d.offline.store(true, Ordering::Relaxed);
    assert_eq!(
        crate::healauto::heal_auto_standdown(&d),
        Some("the daemon is offline")
    );
    assert_eq!(
        crate::healauto::heal_auto_sweep(&d, &dirs, None).verified,
        0
    );
    assert_eq!(heal_rows(&d), 0);
    let _ = std::fs::remove_dir_all(lib.parent().expect("parent"));
}

/// The walk finds folders that carry a settle manifest and nothing
/// else - not their parents, not their subfolders, not a folder that
/// merely holds media. On an install where `write_manifest` has never
/// been on, that is every folder, and the sweep has nothing to do.
#[test]
fn the_walk_finds_manifest_folders_and_only_those() {
    let dir = tdir("walk");
    let lib = dir.join("library");
    let with = lib.join("Show").join("Season 01");
    let without = lib.join("Other");
    std::fs::create_dir_all(&with).expect("with");
    std::fs::create_dir_all(&without).expect("without");
    std::fs::write(without.join("movie.mkv"), body(64, 7)).expect("media");
    settle(
        &with,
        EP1,
        "sha-walk",
        &[("Show - S01E01.mkv", body(8_192, 1))],
    );

    assert_eq!(manifest_dirs(&lib), vec![with], "only the settled folder");
    assert!(
        manifest_dirs(&without).is_empty(),
        "a folder with no manifest is invisible to the sweep"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The cursor. A library bigger than one sweep is covered ACROSS
/// sweeps rather than by re-reading its first folders every time, and a
/// library that fits in one sweep resets to the top rather than
/// re-reading its last folder first forever.
#[test]
fn the_cursor_carries_a_sweep_to_where_the_last_one_stopped() {
    let dir = tdir("cursor");
    let d = test_daemon(&dir);
    d.heal_auto.enabled.store(true, Ordering::Relaxed);
    let lib = dir.join("library");
    for n in ["a", "b", "c"] {
        let f = lib.join(n);
        std::fs::create_dir_all(&f).expect("folder");
        settle(&f, EP1, &format!("sha-{n}"), &[("x.mkv", body(8_192, 1))]);
    }
    let dirs = manifest_dirs(&lib);
    assert_eq!(dirs.len(), 3, "{dirs:?}");

    // The whole list fits in one sweep, so the cursor resets and the
    // next sweep starts at the top again.
    let out = crate::healauto::heal_auto_sweep(&d, &dirs, None);
    assert_eq!(out.verified, 3, "{out:?}");
    assert_eq!(out.resume_after, None, "a covered list rewinds: {out:?}");

    // ...and a resume point lands strictly AFTER the folder named, by
    // path order, whether or not that folder is still in the list.
    let out = crate::healauto::heal_auto_sweep(&d, &dirs[..2], Some(&dirs[0]));
    assert_eq!(out.verified, 2, "wraps rather than stopping: {out:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The budget arithmetic, without a daemon or a disk. Every arm of the
/// automatic road's spending decision, including the two orderings that
/// matter: a target that is over the byte ceiling is refused for THAT
/// rather than for the job count, and vice versa.
#[test]
fn the_spending_decision_is_the_whole_of_the_automatic_rules() {
    let rec = |bytes| RecordedPost {
        nzo_id: "n".into(),
        category: String::new(),
        nzb: PathBuf::from("/nowhere.nzb"),
        total_bytes: bytes,
    };
    let full = SweepBudget {
        jobs_left: 4,
        bytes_left: 10_000,
    };
    assert_eq!(
        auto_admits(None, &full).err(),
        Some(AutoRefusal::NotRecorded)
    );
    assert_eq!(
        auto_admits(Some(&rec(0)), &full).err(),
        Some(AutoRefusal::SizeUnknown)
    );
    assert_eq!(
        auto_admits(Some(&rec(9_999)), &full).map(|r| r.total_bytes),
        Ok(9_999)
    );
    assert_eq!(
        auto_admits(Some(&rec(10_001)), &full).err(),
        Some(AutoRefusal::ByteBudget)
    );
    let spent = SweepBudget {
        jobs_left: 0,
        bytes_left: 10_000,
    };
    assert_eq!(
        auto_admits(Some(&rec(1)), &spent).err(),
        Some(AutoRefusal::JobBudget),
        "the job ceiling is asked before the byte one, so a sweep that \
         has started its allowance says so rather than blaming the size"
    );
}

/// The shipped defaults, pinned by name. A default that moves is a
/// product decision, and this is what makes it one somebody had to
/// write down rather than one that happened.
#[test]
fn the_shipped_defaults_are_off_weekly_four_jobs_and_twenty_gigabytes() {
    let s = HealAutoSettings::default();
    assert!(!s.enabled.load(Ordering::Relaxed));
    assert_eq!(s.interval_h.load(Ordering::Relaxed), 168);
    assert_eq!(s.max_jobs.load(Ordering::Relaxed), 4);
    assert_eq!(s.max_bytes.load(Ordering::Relaxed), 20_000_000_000);
    assert!(
        (s.max_jobs.load(Ordering::Relaxed) as usize) < super::heal::MAX_HEAL_JOBS,
        "an unattended sweep starts fewer repairs than a person who clicked"
    );
}
