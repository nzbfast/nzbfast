//! §296: per-file early publish, measured as an A/B.
//!
//! A submodule of the daemon target rather than its own `tests/*.rs`,
//! for the reason every sibling here is one: a top-level file would
//! become a separate target and fall out of the standard daemon gate.
//!
//! The A/B this drives: a three-file "season pack" where the LAST file
//! is slow to arrive (every one of its articles sits in `slow_ttfb`
//! dead air), and the number being measured is wall-clock from the
//! moment the job is added to the moment episode 1 exists, whole, at
//! the destination folder - time-to-USABLE, which is the metric this
//! whole feature is about.
//!
//! Leg A is the baseline, the tree as it stands with the setting off:
//! nothing reaches the destination until the download drains, settles,
//! runs the finalize tail and the whole-job move. Leg B is the arm
//! live. Both legs run on the SAME rig, in the same process, against
//! the same mock, and both print their number so it is in the test log
//! rather than a claim in a comment.
//!
//! One file, not three, is what this rig publishes early, and that is
//! the pool doing its job rather than a limit of the feature: with one
//! connection the plan interleaves episode 2's articles with the slow
//! episode 3's, so the two drain together at the end. Episode 1 is the
//! one that finishes alone, which is exactly the file the measurement
//! is about - and the end-state assertions still hold the destination
//! to all three, each exactly once, whichever route they took.
//!
//! Two posts, not one post twice. §292's message-id duplicate arm holds
//! a second grab of the same post, so re-adding one NZB would measure
//! the dupe ladder rather than this. The legs carry independently
//! seeded payloads under their own names.

use super::*;

/// Is the external `par2` binary available? Every recovery set below is
/// built by it, and it is not on every box.
fn have_par2() -> bool {
    Command::new("par2")
        .arg("-V")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Article size for the payload files. Small enough that a slow file is
/// many round trips of dead air, large enough that a 3 MB file is not
/// thousands of articles.
const ART: usize = 128 * 1024;

/// Per-article dead air on the slow file. Its whole point is to open a
/// window between "episode 1 is verified" and "the job is finished"
/// that a wall-clock reading can see - and one wider than the
/// publisher's own poll, or the measurement is of the poll.
const SLOW_MS: u64 = 250;

/// One leg's post: three payload files plus the recovery set that
/// covers them, as articles and as NZB `<file>` entries.
struct Post {
    xml: String,
    /// Every article of the last data file - the ones made slow.
    slow: Vec<String>,
}

/// Build a leg's post under `dir`, seeding the payload from `seed` so
/// the two legs are different posts rather than two grabs of one.
///
/// Returns None when `par2 create` declines, which the caller has
/// already guarded for.
fn build_post(
    dir: &Path,
    seed: u8,
    tag: &str,
    articles: &mut HashMap<String, Vec<u8>>,
) -> Option<Post> {
    let work = dir.join(format!("build-{tag}"));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();
    // Three "episodes", each comfortably over the 1 MiB floor below
    // which early publish does not bother.
    let names: Vec<String> = (1..=3).map(|i| format!("{tag}.S01E0{i}.mkv")).collect();
    for (i, n) in names.iter().enumerate() {
        std::fs::write(
            work.join(n),
            payload(3 << 20, seed.wrapping_add(i as u8 * 7)),
        )
        .unwrap();
    }
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let st = Command::new("par2")
        .arg("create")
        .arg("-r5")
        .arg("-q")
        .arg(format!("{tag}set"))
        .args(&refs)
        .current_dir(&work)
        .status();
    if !matches!(st, Ok(s) if s.success()) {
        return None;
    }
    let mut files: Vec<(String, Vec<(String, u64, u32)>)> = Vec::new();
    let mut slow = Vec::new();
    for (i, n) in names.iter().enumerate() {
        let data = std::fs::read(work.join(n)).unwrap();
        let segs = make_file_articles(n, &data, ART, &format!("{tag}d{i}"), articles);
        if i == 2 {
            slow = segs.iter().map(|(id, _, _)| id.clone()).collect();
        }
        files.push((n.clone(), segs));
    }
    let mut par2s: Vec<PathBuf> = std::fs::read_dir(&work)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "par2"))
        .collect();
    par2s.sort();
    for (i, p) in par2s.iter().enumerate() {
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        let data = std::fs::read(p).unwrap();
        let segs = make_file_articles(&name, &data, ART, &format!("{tag}p{i}"), articles);
        files.push((name, segs));
    }
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for (name, segs) in &files {
        xml.push_str(&format!(
            "  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        ));
        for (id, bytes, num) in segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n");
    }
    xml.push_str("</nzb>\n");
    let _ = std::fs::remove_dir_all(&work);
    Some(Post { xml, slow })
}

/// Episode 1 reaches the completed folder while episode 3 is still on
/// the wire - and the baseline, measured on the same rig, does not.
#[tokio::test(flavor = "multi_thread")]
async fn episode_one_lands_at_the_destination_while_episode_three_downloads() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let dir = std::env::temp_dir().join(format!("nzbfast-earlyfile-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let mut articles = HashMap::new();
    // Leg B first, leg A second, each its own post. Which order they run
    // in does not matter; that they are DIFFERENT posts does - see the
    // module docs.
    let Some(treat) = build_post(&dir, 11, "Treat", &mut articles) else {
        eprintln!("skipping: par2 create declined");
        return;
    };
    let Some(base) = build_post(&dir, 47, "Basel", &mut articles) else {
        eprintln!("skipping: par2 create declined");
        return;
    };
    // The slow file, in both posts: every article of episode 3 answers
    // only after `SLOW_MS` of dead air, on EVERY request. That is what
    // opens the window between "episode 1 verified" and "the job is
    // done" - without it a localhost mock finishes all three files
    // inside the poll interval and there is nothing to measure.
    let mut chaos = Chaos::default();
    for id in treat.slow.iter().chain(base.slow.iter()) {
        // Angle brackets: the mock keys its chaos maps on the id as it
        // appears on the BODY line, which is the bracketed form.
        chaos.slow_ttfb.insert(format!("<{id}>"), SLOW_MS);
    }
    let srv = MockServer::start(articles, chaos).await;

    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false}}]}}",
            srv.addr.ip(),
            srv.addr.port()
        ),
    )
    .unwrap();
    let nas = dir.join("library");
    std::fs::create_dir_all(&nas).unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"))
            // ONE connection, so the pack downloads in NZB order and the
            // slow file's dead air is serial rather than divided by the
            // fleet. The window this measures has to be wider than the
            // publisher's own poll, and a deterministic window beats a
            // wide one that depends on how the plan spread the articles.
            .arg("--connections")
            .arg("1");
        c
    })
    .await;
    let port = d.port;
    let nas2 = nas.clone();
    let src_root = dir.join("complete");

    tokio::task::spawn_blocking(move || {
        let set = |name: &str, value: &str| {
            let r = http(
                port,
                &format!(
                    "/api?mode=config&name={name}&value={}&output=json",
                    urlenc(value)
                ),
                None,
            );
            assert!(r.contains("true"), "{name} was not accepted: {r}");
        };
        set("move_completed", &nas2.to_string_lossy());
        // The *arr shape, and the only one §296 engages for: the
        // finalize tail must not rename, file or sweep anything, or the
        // destination path and the file's own name are not final at the
        // moment the copy would be taken.
        for off in ["auto_rename", "rename_junk", "rename_media_only"] {
            set(off, "0");
        }

        let upload = |fname: &str, xml: &str| -> String {
            let boundary = "----earlyfileb";
            let mut body = Vec::new();
            body.extend_from_slice(
                format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{fname}\"\r\n\r\n").as_bytes(),
            );
            body.extend_from_slice(xml.as_bytes());
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            let r = http(
                port,
                "/api?mode=addfile&output=json",
                Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
            );
            assert!(r.contains("\"status\":true"), "{r}");
            r.split("SABnzbd_nzo_")
                .nth(1)
                .and_then(|s| s.split('"').next())
                .map(|s| format!("SABnzbd_nzo_{s}"))
                .expect("addfile returned no nzo_id")
        };
        // A TERMINAL verdict, and only that. A parked job appears in
        // history before its move has run, wearing the transient
        // "Moving" word for as long as the copy takes - so taking the
        // first status this row shows reads a job that is still moving
        // as one that is done, which is the wrong instant for both legs
        // and read as a failure in the treatment one.
        let terminal = |id: &str| -> Option<String> {
            let h = http(port, "/api?mode=history&output=json", None);
            let v: serde_json::Value = serde_json::from_str(&h).unwrap_or(serde_json::Value::Null);
            v["history"]["slots"].as_array().and_then(|s| {
                s.iter()
                    .find(|x| x["nzo_id"] == id)
                    .and_then(|x| x["status"].as_str())
                    .filter(|st| matches!(*st, "Completed" | "Failed"))
                    .map(str::to_string)
            })
        };
        // Whole means WHOLE: the size the payload was built at. A copy
        // that is merely present is exactly the failure the atomic
        // publish exists to prevent, so the measurement asks for the
        // finished file and never for the name.
        let whole = |p: &Path| p.metadata().map(|m| m.len()).unwrap_or(0) == (3 << 20);
        let find_ep1 = |tag: &str| -> Option<PathBuf> {
            for e in std::fs::read_dir(&nas2).ok()?.flatten() {
                let p = e.path().join(format!("{tag}.S01E01.mkv"));
                if whole(&p) {
                    return Some(p);
                }
            }
            None
        };
        // How many of this job's files `mode=get_files` currently calls
        // "published" - §296's own state word, and the ONLY thing in any
        // payload that tells a user watching a slow pack that episode 1
        // is already usable. Read live rather than after the fact: the
        // record it comes from is spent by the reconcile at move time, so
        // a check that waits for the job to finish can never see it.
        let published_now = |id: &str| -> usize {
            let r = http(
                port,
                &format!("/api?mode=get_files&value={id}&output=json"),
                None,
            );
            let v: serde_json::Value = serde_json::from_str(&r).unwrap_or(serde_json::Value::Null);
            v["files"]
                .as_array()
                .map(|f| f.iter().filter(|x| x["state"] == "published").count())
                .unwrap_or(0)
        };
        // One leg: add, then poll for episode 1 at the destination and
        // for the job's own terminal row, timing both from the add. The
        // third reading is the drawer's - the most files the listing ever
        // called "published" while the job was still running.
        let leg = |tag: &str, nzb: &str, xml: &str| -> (f64, f64, String, usize) {
            let t0 = std::time::Instant::now();
            let id = upload(nzb, xml);
            let (mut usable, mut done, mut said) = (None, None, 0usize);
            for _ in 0..1200 {
                if usable.is_none() && find_ep1(tag).is_some() {
                    usable = Some(t0.elapsed().as_secs_f64());
                }
                if done.is_none() {
                    // Only while the job is still live: once it parks,
                    // the reconcile has spent the record and the listing
                    // is answered from somewhere else entirely.
                    said = said.max(published_now(&id));
                    if let Some(st) = terminal(&id) {
                        done = Some((t0.elapsed().as_secs_f64(), st));
                    }
                }
                // The move runs off the finalize tail, so a terminal
                // history row does not mean the files have landed - keep
                // polling until BOTH answers are in.
                if usable.is_some() && done.is_some() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            let (dt, st) = done.expect("the job never reached a terminal row");
            (usable.unwrap_or(f64::INFINITY), dt, st, said)
        };

        // ---- Leg B: the arm live ----
        set("early_file_publish", "1");
        let (b_usable, b_done, b_status, b_said) = leg("Treat", "treat.nzb", &treat.xml);
        assert_eq!(b_status, "Completed", "the treatment job did not complete");

        // ---- Leg A: the baseline, same rig ----
        set("early_file_publish", "0");
        let (a_usable, a_done, a_status, a_said) = leg("Basel", "basel.nzb", &base.xml);
        assert_eq!(a_status, "Completed", "the baseline job did not complete");

        println!(
            "A/B §296 time-to-usable (episode 1 whole at the destination), \
             3x3 MiB pack, episode 3 at {SLOW_MS} ms dead air per article:\n  \
             leg A (baseline, whole-job move): {a_usable:.2}s usable, {a_done:.2}s complete\n  \
             leg B (§296 live):                {b_usable:.2}s usable, {b_done:.2}s complete\n  \
             episode 1 arrived {:.2}s sooner ({:.0}% of the baseline's wait)",
            a_usable - b_usable,
            100.0 * b_usable / a_usable
        );

        // The DRAWER's half of it: a user watching this pack can see that
        // episode 1 is already usable, which is the whole reason the word
        // exists. Asserted on both legs, because a state word that shows
        // up with the feature OFF would be the listing inventing a claim
        // nothing published.
        println!(
            "  drawer: {b_said} row(s) read \"published\" mid-job with the arm live, \
             {a_said} with it off"
        );
        assert!(
            b_said >= 1,
            "no row ever reported the published state while the job ran"
        );
        assert_eq!(
            a_said, 0,
            "the baseline publishes nothing, so no row may claim it"
        );

        // The claim, and nothing stronger than the rig can support.
        assert!(
            b_usable < b_done,
            "leg B published episode 1 BEFORE its job finished: \
             {b_usable:.2}s usable vs {b_done:.2}s complete"
        );
        // The baseline cannot put anything at the destination before its
        // whole-job move, which runs off the finalize tail - so its two
        // readings land in the same 50 ms poll and the loop, which asks
        // about the file first, records that one fractionally earlier.
        // The slack is that artefact and nothing else; the substance is
        // that the baseline has NO window at all, which is what leg B's
        // six seconds are measured against.
        assert!(
            a_usable + 0.25 >= a_done,
            "the baseline cannot publish anything before the whole-job move: \
             {a_usable:.2}s usable vs {a_done:.2}s complete"
        );
        assert!(
            b_usable < a_usable,
            "the whole point: {b_usable:.2}s vs the baseline's {a_usable:.2}s"
        );

        // ...and the end state is the SAME state. An early publish that
        // wins the race and loses a file, duplicates one, or leaves the
        // payload split across the download folder and the destination
        // has not made anything faster.
        for (tag, other) in [("Treat", "Basel"), ("Basel", "Treat")] {
            let ep1 = find_ep1(tag).unwrap_or_else(|| panic!("{tag} episode 1 is not whole"));
            let jobdir = ep1.parent().unwrap().to_path_buf();
            let mut got: Vec<String> = std::fs::read_dir(&jobdir)
                .unwrap()
                .flatten()
                .map(|e| e.file_name().to_string_lossy().to_string())
                .filter(|n| n.ends_with(".mkv"))
                .collect();
            got.sort();
            assert_eq!(
                got,
                vec![
                    format!("{tag}.S01E01.mkv"),
                    format!("{tag}.S01E02.mkv"),
                    format!("{tag}.S01E03.mkv"),
                ],
                "{tag}: the destination must hold each episode exactly once \
                 (a duplicate here is move_tree merging over an early copy)"
            );
            for n in &got {
                assert!(
                    whole(&jobdir.join(n)),
                    "{tag}: {n} is not the size it was posted at"
                );
                assert!(
                    !n.contains(other),
                    "{tag}: a file from the other leg reached this folder"
                );
            }
            // Nothing of the payload left behind in the download folder:
            // the reconcile removes the source of every file it kept,
            // and the move carries the rest.
            let strays: Vec<String> = walk_mkv(&src_root)
                .into_iter()
                .filter(|n| n.starts_with(tag))
                .collect();
            assert!(
                strays.is_empty(),
                "{tag}: payload left in the download folder: {strays:?}"
            );
        }
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Every `.mkv` under `root`, by leaf name.
fn walk_mkv(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(root) else {
        return out;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk_mkv(&p));
        } else if p.extension().is_some_and(|x| x == "mkv") {
            out.push(p.file_name().unwrap().to_string_lossy().to_string());
        }
    }
    out
}
