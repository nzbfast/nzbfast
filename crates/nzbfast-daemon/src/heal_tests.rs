//! §310 stage 2. The rules the heal wiring is made of, each with a test
//! that fails if it is quietly removed:
//!
//! * the grouping is BY PROVENANCE, not by directory. A season folder
//!   re-fetches a different post per episode, which is the whole reason
//!   stage 1 put `job`/`sha` on the ENTRY rather than on the manifest.
//! * a consumed archive volume is not damage. Convicting it would
//!   report every extracted job broken.
//! * extracted output IS damage when it rots, and the post it names is
//!   the archive post that produced it. That is TODO 310's third box,
//!   landed 2 Sep 2026: before it the film a user actually keeps was a
//!   presence entry and this module could not see it rot at all.
//! * a heal job carries the library folder, so §293's adoption scan
//!   reads the intact bytes off the disk instead of the wire.
//! * the offer spends nothing.
//! * BOTH roads through `heal_one` run. The recorded post first, and
//!   the §282 search when its spooled `.nzb` is gone with its history
//!   record - which is the road every folder older than its own history
//!   takes, and the one the manifest's per-entry provenance exists to
//!   keep aimable.

use super::*;
use crate::manifest::Manifest;
use crate::testutil::test_daemon;
use nzbkit::par2::{BlockCheck, Par2File, Par2Set};

fn tdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "nzbfast-heal-{tag}-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("t").len()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("temp dir");
    d
}

/// Deterministic junk that is not all-zero, so a flipped byte actually
/// changes a checksum.
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

/// A real `Par2Set` over generated payload, the way the parser would
/// have built it. Same shape as `manifest::tests::set_over`, which is
/// private to that module.
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

/// Settle one job's payload into `dir`: write the files, then merge its
/// PAR2 set into the directory's manifest exactly as `postproc` does.
fn settle(dir: &Path, job: &str, sha: &str, files: &[(&str, Vec<u8>)], archive: bool) {
    for (n, d) in files {
        std::fs::write(dir.join(n), d).expect("payload");
    }
    let refs: Vec<(&str, &[u8])> = files.iter().map(|(n, d)| (*n, d.as_slice())).collect();
    let set = set_over(&refs, 4096);
    Manifest::from_set(&set, job, sha, archive)
        .write_reconciled(dir)
        .expect("manifest");
}

/// Flip one byte in the middle of a settled file.
fn damage(dir: &Path, name: &str) {
    let p = dir.join(name);
    let mut b = std::fs::read(&p).expect("read back");
    let at = b.len() / 2;
    b[at] ^= 0x40;
    std::fs::write(&p, b).expect("damage");
}

const EP1: &str = "Show.S01E01.1080p.WEB-DL.x264-GRP";
const EP2: &str = "Show.S01E02.1080p.WEB-DL.x264-GRP";

/// THE RULE THIS BOX EXISTS FOR. A TV-filed season folder is ONE
/// directory holding files proved by SEVERAL posts, and the post to
/// re-fetch differs per episode - which is why stage 1 put the
/// provenance on the entry. Damage one file from each of two episodes
/// and the plan must be two targets, each naming its own post and its
/// own file, with the intact third episode nowhere in it.
#[test]
fn two_damaged_episodes_re_hunt_their_own_posts() {
    let dir = tdir("season");
    settle(
        &dir,
        EP1,
        "sha-ep1",
        &[("Show - S01E01.mkv", body(20_000, 1))],
        false,
    );
    settle(
        &dir,
        EP2,
        "sha-ep2",
        &[("Show - S01E02.mkv", body(20_000, 2))],
        false,
    );
    settle(
        &dir,
        "Show.S01E03.1080p.WEB-DL.x264-GRP",
        "sha-ep3",
        &[("Show - S01E03.mkv", body(20_000, 3))],
        false,
    );
    damage(&dir, "Show - S01E01.mkv");
    damage(&dir, "Show - S01E02.mkv");

    let p = plan(&dir).expect("plan");
    assert!(p.unidentified.is_empty(), "{p:?}");
    assert_eq!(p.targets.len(), 2, "one target per damaged POST: {p:?}");
    let ep1 = p
        .targets
        .iter()
        .find(|t| t.nzb_sha == "sha-ep1")
        .expect("episode 1's own post");
    assert_eq!(ep1.job, EP1);
    assert_eq!(ep1.files, vec!["Show - S01E01.mkv".to_string()]);
    let ep2 = p
        .targets
        .iter()
        .find(|t| t.nzb_sha == "sha-ep2")
        .expect("episode 2's own post");
    assert_eq!(ep2.job, EP2);
    assert_eq!(ep2.files, vec!["Show - S01E02.mkv".to_string()]);
    assert!(
        !p.targets.iter().any(|t| t.nzb_sha == "sha-ep3"),
        "the intact episode's post is not re-fetched: {p:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The other half of the same rule: several damaged files that share
/// one post are ONE download, not one per file.
#[test]
fn several_damaged_files_from_one_post_are_one_target() {
    let dir = tdir("onepost");
    settle(
        &dir,
        "Film.2019.2160p.UHD.BluRay-GRP",
        "sha-film",
        &[
            ("a.mkv", body(20_000, 4)),
            ("b.mkv", body(20_000, 5)),
            ("c.mkv", body(20_000, 6)),
        ],
        false,
    );
    damage(&dir, "a.mkv");
    damage(&dir, "c.mkv");

    let p = plan(&dir).expect("plan");
    assert_eq!(p.targets.len(), 1, "{p:?}");
    assert_eq!(
        p.targets[0].files,
        vec!["a.mkv".to_string(), "c.mkv".to_string()],
        "both damaged members ride the one re-fetch"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Settle an archive post the way the tail leaves one: the covered
/// volume recorded and then swept, the extracted film left behind and
/// hashed off the disk by the reconcile.
fn settle_extracted_archive(dir: &Path, job: &str, sha: &str, film: &[u8]) {
    settle(dir, job, sha, &[("set.part1.rar", body(20_000, 7))], true);
    std::fs::remove_file(dir.join("set.part1.rar")).expect("sweep the volume");
    std::fs::write(dir.join("Film.mkv"), film).expect("extract");
    Manifest::load(dir)
        .expect("load")
        .clone()
        .write_reconciled(dir)
        .expect("re-reconcile");
}

/// A PAR2-covered archive volume the unpack tail consumed is the NORMAL
/// end state and is not damage - a plan that thought otherwise would ask
/// to re-download every extracted job in the library. The film beside
/// it is intact, and now that it carries a grid, "intact" is a thing
/// this can actually say about it rather than a thing it assumed.
#[test]
fn a_consumed_volume_is_not_damage() {
    let dir = tdir("archive");
    settle_extracted_archive(
        &dir,
        "Film.2020.1080p.BluRay-GRP",
        "sha-arc",
        &body(50_000, 8),
    );

    let p = plan(&dir).expect("plan");
    assert!(p.is_empty(), "nothing here is damage: {p:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// TODO 310's third box, from this side. An archive post's PAR2 set
/// covers the VOLUMES, so until 2 Sep 2026 the extracted film was a
/// presence entry with no checksum on it: it could rot and `plan` would
/// report the folder clean, which is the whole feature blind to most of
/// a real library. `write_reconciled` now reads it and records a CRC32
/// grid, so a flipped byte is damage and the post it names is the
/// archive post that produced it.
///
/// The heal that follows re-fetches that post in FULL rather than the
/// damaged remainder - the folder holds the extracted film and the
/// fresh set describes the volumes, so `donor_dirs` has nothing to
/// recognise. That is stated in this module's header and is not a
/// reason to withhold the detection; the alternative was a film that
/// rots unnoticed.
#[test]
fn a_rotted_extracted_film_names_the_archive_post_that_made_it() {
    let dir = tdir("rot");
    settle_extracted_archive(
        &dir,
        "Film.2020.1080p.BluRay-GRP",
        "sha-arc",
        &body(50_000, 8),
    );
    damage(&dir, "Film.mkv");

    let p = plan(&dir).expect("plan");
    assert!(p.unidentified.is_empty(), "{p:?}");
    assert_eq!(p.targets.len(), 1, "{p:?}");
    assert_eq!(p.targets[0].nzb_sha, "sha-arc");
    assert_eq!(p.targets[0].job, "Film.2020.1080p.BluRay-GRP");
    assert_eq!(p.targets[0].files, vec!["Film.mkv".to_string()]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A damaged entry the manifest cannot attribute is REPORTED, never
/// dropped. A user told only about the healable half would read the
/// silence as health.
#[test]
fn an_entry_with_no_provenance_is_reported_rather_than_dropped() {
    let dir = tdir("noprov");
    settle(&dir, "", "", &[("orphan.bin", body(20_000, 9))], false);
    damage(&dir, "orphan.bin");

    let p = plan(&dir).expect("plan");
    assert!(p.targets.is_empty(), "{p:?}");
    assert_eq!(p.unidentified, vec!["orphan.bin".to_string()]);
    assert!(!p.is_empty(), "the folder is damaged, and says so");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Stand a history record up for a settled post, with its spooled .nzb
/// on disk, and hand back the sha the manifest must carry to match it.
fn record_post(d: &Daemon, dir: &Path, id: &str, name: &str) -> String {
    let nzb = dir.join(format!("{id}.nzb"));
    let xml = format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\
         <file poster=\"x\" date=\"1700000000\" subject=\"&quot;{id}.bin&quot; yEnc (1/1)\">\
         <groups><group>g</group></groups><segments>\
         <segment bytes=\"1000\" number=\"1\">{id}@e</segment></segments></file></nzb>"
    );
    std::fs::write(&nzb, &xml).expect("spool nzb");
    let sha = nzb_sha(xml.as_bytes());
    d.history.lock_ok().push(Arc::new(Mutex::new(
        job_from_json(&serde_json::json!({
            "nzo_id": id, "name": name, "origin": "dashboard",
            "state": "Completed",
            "out_dir": dir.to_string_lossy(),
            "nzb_path": nzb.to_string_lossy(),
            "nzb_sha": sha,
        }))
        .expect("history row"),
    )));
    sha
}

/// THE WIRING, end to end on the recorded-post road: damage a settled
/// file, ask for a heal, and the queue gains ONE job that carries the
/// library folder - which is what `tasks::worker` turns into
/// `donor_dirs`, and therefore what makes the repair cheap instead of a
/// second full download.
#[test]
fn a_heal_queues_the_recorded_post_with_the_library_folder_as_a_donor() {
    let dir = tdir("start");
    let d = test_daemon(&dir);
    let lib = dir.join("library");
    std::fs::create_dir_all(&lib).expect("library");
    let sha = record_post(&d, &dir, "nzo-ep1", EP1);
    settle(
        &lib,
        EP1,
        &sha,
        &[("Show - S01E01.mkv", body(20_000, 1))],
        false,
    );
    damage(&lib, "Show - S01E01.mkv");

    let out = crate::heal::heal_start(&d, &lib.to_string_lossy(), "").expect("the heal is offered");
    assert_eq!(
        out["refused"].as_array().map(Vec::len),
        Some(0),
        "nothing refused: {out}"
    );
    assert_eq!(out["started"].as_array().map(Vec::len), Some(1), "{out}");
    assert_eq!(out["started"][0]["replaces"], serde_json::json!("nzo-ep1"));

    let row = {
        let q = d.queue.lock_ok();
        q.iter()
            .map(|j| j.lock_ok())
            .find(|g| g.origin == format!("heal:{sha}"))
            .map(|g| (g.name.clone(), g.heal_dir.clone(), g.paused, g.priority))
            .expect("a heal row on the queue")
    };
    assert_eq!(
        row.1, lib,
        "the damaged folder rides along as the donor directory"
    );
    // The add is `-2` so the row cannot be picked before the donor is
    // stamped on it; what must never survive that is the PAUSE itself,
    // or the repair the user asked for sits there doing nothing. -2 is
    // "add paused" and not a priority, so the row is Normal.
    assert!(!row.2, "the heal is released once its donor is stamped");
    assert_eq!(row.3, 0, "add-paused is not a priority");
    assert_eq!(row.0, EP1, "queued under the release, not the file");
    let _ = std::fs::remove_dir_all(&dir);
}

/// ...and the season folder again, this time through the daemon: two
/// damaged episodes give TWO heal jobs, each pointed at its own post,
/// both donating from the one folder.
#[test]
fn each_damaged_episode_gets_its_own_heal_job() {
    let dir = tdir("season-start");
    let d = test_daemon(&dir);
    let lib = dir.join("library");
    std::fs::create_dir_all(&lib).expect("library");
    let sha1 = record_post(&d, &dir, "nzo-ep1", EP1);
    let sha2 = record_post(&d, &dir, "nzo-ep2", EP2);
    settle(
        &lib,
        EP1,
        &sha1,
        &[("Show - S01E01.mkv", body(20_000, 1))],
        false,
    );
    settle(
        &lib,
        EP2,
        &sha2,
        &[("Show - S01E02.mkv", body(20_000, 2))],
        false,
    );
    damage(&lib, "Show - S01E01.mkv");
    damage(&lib, "Show - S01E02.mkv");

    let out = crate::heal::heal_start(&d, &lib.to_string_lossy(), "").expect("heal");
    assert_eq!(out["started"].as_array().map(Vec::len), Some(2), "{out}");

    let q = d.queue.lock_ok();
    let rows: Vec<(String, String, PathBuf)> = q
        .iter()
        .map(|j| j.lock_ok())
        .filter(|g| g.origin.starts_with("heal:"))
        .map(|g| (g.origin.clone(), g.name.clone(), g.heal_dir.clone()))
        .collect();
    drop(q);
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert!(
        rows.iter()
            .any(|(o, n, h)| *o == format!("heal:{sha1}") && n == EP1 && *h == lib),
        "episode 1 re-fetches its OWN post: {rows:?}"
    );
    assert!(
        rows.iter()
            .any(|(o, n, h)| *o == format!("heal:{sha2}") && n == EP2 && *h == lib),
        "episode 2 re-fetches its OWN post: {rows:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A second click is not a second download. The add is
/// `DupeExempt::Anybody` - it has to be, a heal IS a duplicate of the
/// completed row - so the duplicate ladder is not there to catch this
/// and the heal road owns the refusal itself.
#[test]
fn a_repair_already_on_the_queue_is_not_started_twice() {
    let dir = tdir("twice");
    let d = test_daemon(&dir);
    let lib = dir.join("library");
    std::fs::create_dir_all(&lib).expect("library");
    let sha = record_post(&d, &dir, "nzo-ep1", EP1);
    settle(
        &lib,
        EP1,
        &sha,
        &[("Show - S01E01.mkv", body(20_000, 1))],
        false,
    );
    damage(&lib, "Show - S01E01.mkv");

    crate::heal::heal_start(&d, &lib.to_string_lossy(), "").expect("first");
    let again = crate::heal::heal_start(&d, &lib.to_string_lossy(), "").expect("second");
    assert_eq!(
        again["started"].as_array().map(Vec::len),
        Some(0),
        "{again}"
    );
    assert_eq!(
        again["refused"].as_array().map(Vec::len),
        Some(1),
        "{again}"
    );
    assert!(
        again["refused"][0]["error"]
            .as_str()
            .unwrap_or_default()
            .contains("already on the queue"),
        "{again}"
    );
    let heals = d
        .queue
        .lock_ok()
        .iter()
        .filter(|j| j.lock_ok().origin.starts_with("heal:"))
        .count();
    assert_eq!(heals, 1, "one repair, not two");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The offer REPORTS and does not spend: it names the damage and the
/// post each piece needs, and the queue is untouched afterwards. A
/// command that answers a question by starting a download is one nobody
/// can run safely.
#[test]
fn the_offer_names_the_source_and_queues_nothing() {
    let dir = tdir("offer");
    let d = test_daemon(&dir);
    let lib = dir.join("library");
    std::fs::create_dir_all(&lib).expect("library");
    let sha = record_post(&d, &dir, "nzo-ep1", EP1);
    settle(
        &lib,
        EP1,
        &sha,
        &[("Show - S01E01.mkv", body(20_000, 1))],
        false,
    );
    damage(&lib, "Show - S01E01.mkv");

    let before = d.queue.lock_ok().len();
    let v = crate::heal::heal_offer(&d, &lib.to_string_lossy()).expect("offer");
    assert_eq!(v["targets"].as_array().map(Vec::len), Some(1), "{v}");
    assert_eq!(v["targets"][0]["source"], serde_json::json!("recorded"));
    assert_eq!(v["targets"][0]["nzb_sha"], serde_json::json!(sha));
    assert_eq!(v["targets"][0]["name"], serde_json::json!(EP1));
    assert_eq!(
        d.queue.lock_ok().len(),
        before,
        "the offer enqueued something"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A release name a search cannot be AIMED with is said so on the
/// read-only door, not discovered at the second click. An obfuscated
/// stem answers neither `target_keys` nor `dupe_key`, and with its
/// history record gone there is no post to re-fetch either.
#[test]
fn a_name_no_search_can_be_aimed_with_is_reported_as_such() {
    let dir = tdir("obfuscated");
    let d = test_daemon(&dir);
    let lib = dir.join("library");
    std::fs::create_dir_all(&lib).expect("library");
    settle(
        &lib,
        "a7f3c19e04bb2d",
        "sha-obf",
        &[("a7f3c19e04bb2d.bin", body(20_000, 1))],
        false,
    );
    damage(&lib, "a7f3c19e04bb2d.bin");

    let v = crate::heal::heal_offer(&d, &lib.to_string_lossy()).expect("offer");
    assert_eq!(v["targets"][0]["source"], serde_json::json!("none"), "{v}");
    // ...and the spending door agrees rather than starting something.
    let out = crate::heal::heal_start(&d, &lib.to_string_lossy(), "").expect("start");
    assert_eq!(out["started"].as_array().map(Vec::len), Some(0), "{out}");
    assert_eq!(out["refused"].as_array().map(Vec::len), Some(1), "{out}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A folder with no manifest is not a folder with no damage. Both doors
/// say so rather than answering "clean" - the same distinction
/// `nzbfast verify` draws when it has nothing to check against.
#[test]
fn a_folder_with_no_manifest_is_refused_rather_than_called_clean() {
    let dir = tdir("nomanifest");
    let d = test_daemon(&dir);
    let lib = dir.join("library");
    std::fs::create_dir_all(&lib).expect("library");
    let err = crate::heal::heal_offer(&d, &lib.to_string_lossy()).expect_err("refused");
    assert!(err.contains("settle manifest"), "{err}");
    assert!(
        crate::heal::heal_start(&d, &lib.to_string_lossy(), "").is_err(),
        "the spending door refuses for the same reason"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The release the search road is driven with. Its own constant rather
/// than `EP1` because this test needs a stem an FTS query can actually
/// be aimed at - a bare "Show" is a poor thing to search a real index
/// for - and because the candidate below has to be a DIFFERENT post of
/// the SAME episode, which is easier to read as a pair.
#[cfg(feature = "indexer")]
const SEARCH_EP: &str = "Some.Show.S01E05.1080p.WEB-DL.x264-GRP";
/// A later post of that same episode, sitting in our own index. A
/// different encode and a different group, so `same_release` has to
/// agree on identity rather than on the string.
#[cfg(feature = "indexer")]
const SEARCH_REPOST: &str = "Some.Show.S01E05.2160p.WEB.H265-REPOST";

/// **THE SEARCH ROAD, end to end.** `heal_one`'s fallback - the branch
/// taken when the post that proved these bytes is no longer on record
/// here - had no test at all until this one: `hunt_by_name`'s only
/// caller outside `hunt.rs` is `heal.rs`, and nothing reached it.
///
/// It is not an exotic road. A manifest is built to OUTLIVE the history
/// record - that is why `Job::heal_dir` is a path rather than a second
/// `alt_from` - so "the record is gone and the name is all we have" is
/// the ordinary shape for the feature's own stated use, a library
/// folder checked years later. Both other `source` values were pinned
/// (`recorded` above, `none` below) and this one, the one every old
/// folder takes, was not.
///
/// **The record is staged and then HALF-removed, and that is the
/// fixture's one real decision.** Simply omitting the history row would
/// reach the same branch, but `recorded_post` has TWO ways of answering
/// `None` and only the second is the shape a real library folder hits:
/// history aged the row out and took its spooled `.nzb` with it, or a
/// user emptied their spool. So the row is stood up exactly as
/// `record_post` does it for the recorded-road tests and its `.nzb` is
/// then deleted, which drives `recorded_post`'s `is_file()` guard on
/// the false side - the guard whose whole job is to fall through to
/// here rather than fail on a read of a file that is gone.
///
/// The replacement can come from ONE place: our own index, seeded the
/// way `hunt_tests`'
/// `a_local_index_replacement_is_found_and_the_same_post_is_refused`
/// seeds it. No mock indexer is registered - `d.indexers` stays empty,
/// so the external arm returns nothing - which is what makes a passing
/// test mean the search actually found and fetched something, with no
/// network anywhere. The queued job's spooled `.nzb` is read back for
/// the article `make_nzb` produced, because a fixture that quietly took
/// the recorded road after all would otherwise pass.
#[cfg(feature = "indexer")]
#[test]
fn a_heal_whose_recorded_post_is_gone_re_fetches_the_release_by_search() {
    let dir = tdir("searchroad");
    let d = test_daemon(&dir);
    let lib = dir.join("library");
    std::fs::create_dir_all(&lib).expect("library");
    // Not load-bearing on top of `test_daemon`'s default `spot_enabled`
    // (which already opens `index_db_wanted()`), but this is what an
    // own-index install actually has on, and the real toggle to name.
    d.index_enabled.store(true, Ordering::Relaxed);

    let sha = record_post(&d, &dir, "nzo-aged", SEARCH_EP);
    std::fs::remove_file(dir.join("nzo-aged.nzb")).expect("the spool copy goes");
    settle(
        &lib,
        SEARCH_EP,
        &sha,
        &[("Some Show - S01E05.mkv", body(20_000, 5))],
        false,
    );
    damage(&lib, "Some Show - S01E05.mkv");

    {
        let mut ix = nzbkit::index::Index::open(&d.index_db).expect("open index");
        ix.ingest(
            "alt.binaries.test",
            &[nzbkit::nntp::OverEntry {
                number: 1,
                subject: format!(r#""{SEARCH_REPOST}.rar" yEnc (1/1)"#),
                from: "poster@example".into(),
                message_id: "<heal-repost@y>".into(),
                bytes: 2_000,
                date: unix_now() - 300 * 86_400,
            }],
            unix_now(),
        )
        .expect("ingest the repost");
    }

    // The read-only door says which road the second click will take,
    // and with no post on record it must say `search` - not `none`,
    // which is what a name no search can be aimed with would get.
    let v = crate::heal::heal_offer(&d, &lib.to_string_lossy()).expect("offer");
    assert_eq!(v["targets"].as_array().map(Vec::len), Some(1), "{v}");
    assert_eq!(
        v["targets"][0]["source"],
        serde_json::json!("search"),
        "{v}"
    );
    assert_eq!(v["targets"][0]["nzo_id"], serde_json::json!(""), "{v}");

    let out = crate::heal::heal_start(&d, &lib.to_string_lossy(), "").expect("start");
    assert_eq!(
        out["refused"].as_array().map(Vec::len),
        Some(0),
        "nothing refused: {out}"
    );
    assert_eq!(out["started"].as_array().map(Vec::len), Some(1), "{out}");
    // What tells the two roads apart from OUTSIDE the daemon. The
    // recorded road answers with the nzo it re-fetched and queues under
    // the damaged release's own name; the search road has no record to
    // replace and queues under the CANDIDATE's stem, which is exactly
    // why `hunt_by_name` hands its stem back.
    assert_eq!(
        out["started"][0]["replaces"],
        serde_json::json!(""),
        "{out}"
    );
    assert_eq!(
        out["started"][0]["name"],
        serde_json::json!(SEARCH_REPOST),
        "{out}"
    );
    assert_eq!(
        out["started"][0]["nzb_sha"],
        serde_json::json!(sha),
        "{out}"
    );

    let (name, heal_dir, paused, nzb_path) = {
        let q = d.queue.lock_ok();
        let job = q
            .iter()
            .find(|j| j.lock_ok().origin == format!("heal:{sha}"))
            .expect("the heal is on the queue under the damaged post's origin");
        let g = job.lock_ok();
        (
            g.name.clone(),
            g.heal_dir.clone(),
            g.paused,
            g.nzb_path.clone(),
        )
    };
    assert_eq!(name, SEARCH_REPOST, "queued under the candidate's stem");
    // The donor economics do not change between the roads: `heal_dir`
    // is what `tasks::worker` turns into `donor_dirs`, and without it
    // this repair is a second full download of the whole release.
    assert_eq!(
        heal_dir, lib,
        "the library folder is stamped on the search road too"
    );
    assert!(!paused, "the repair has to RUN, not sit held");

    // The bytes really came from the search. `make_nzb` synthesised
    // this from the index row above, so its article is the proof no
    // spooled copy of the original post was quietly read instead.
    let nzb = std::fs::read_to_string(&nzb_path).expect("spooled nzb");
    assert!(
        nzb.contains("heal-repost@y"),
        "the queued nzb must carry the article the index synthesised: {nzb}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
