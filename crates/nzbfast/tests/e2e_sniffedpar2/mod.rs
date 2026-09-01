//! A post whose PAR2 files do not announce themselves - the obfuscated
//! recovery set, sniffed rather than named.
//!
//! A sibling-dir child of e2e.rs (the e2e_repair pattern) so the parent
//! stays inside its size-gate baseline. Declared from e2e.rs, so these
//! still run in that binary against those fixtures; helpers via
//! `super::*`.
//!
//! One subject, and it is the one question every leg here turns on: this
//! post's recovery volumes carry no `.par2` extension and no name the
//! set can be found by, so nothing can be classified from the NZB. The
//! offset-0 magic sniff reclassifies each slot IN-STREAM instead - the
//! smallest sniffed file bootstraps the set, the rest defer, and the
//! adoption scan ties a hash-named file on disk back to its FileDesc by
//! CONTENT. Public issue #9 is where it starts (a repairable download
//! failed while SABnzbd repaired it), #14 is the resume half (a
//! journal-completed head never re-decodes, so run 2 must recognise
//! restored volumes by reading their first bytes off disk), and #23 is
//! the coverage rule that came out of it - a set proves the files it
//! covers and nothing else.
//!
//! The last three legs are the mirror image of the same question and
//! belong with it rather than beside the named-PAR2 legs they sat next
//! to: payload that LOOKS like PAR2 to the sniff and is not, which must
//! be un-deferred and delivered byte-exact rather than recreated from
//! recovery blocks.

use super::*;
use crate::payloads;

/// Public issue #9: a fully obfuscated post whose recovery set we could
/// not see, so a repairable download failed while SABnzbd repaired it.
///
/// Nothing here carries a `.par2`: not an NZB subject, not a yEnc name,
/// not a filename on disk. That makes every file arrive classified as
/// payload and `bootstrap_vol` (which only considers files already
/// recognised as recovery volumes) never fires. Since issue #14 the
/// offset-0 magic sniff reclassifies each of those slots in-stream: the
/// smallest sniffed file bootstraps the set, the rest defer, and the
/// damage is repaired through the SAME in-stream ladder a named post
/// uses - exact-fit recovery fetch included. This pins the end-to-end
/// outcome: real damage, real recovery, repaired output, and the
/// activation marker proving it happened in-stream rather than in the
/// disk-side fallback arm.
///
/// **THE PAYLOAD IS `unique_payload` AND THE REBUILT COUNT IS PART OF
/// THE ROW**, here and in the two repairing fixtures below (30 Aug
/// 2026, `research/E2E-PARITY-BUDGET-CENSUS-2026-08-30.md`). On
/// `super::payload` all three greened with `0 block(s) rebuilt ... 200
/// block(s) adopted`: that generator is one sequence of period 131,072,
/// so a 1.2 MB file carries every block of itself nine times over and
/// the sliding scan healed the holes out of the damaged copy without
/// the recovery set being read at all. "Real recovery" was the one
/// clause of the sentence above that nothing tested - the row would
/// have stayed green with every recovery slice empty. splitmix64 leaves
/// the holed blocks nowhere else to be found, so the exact-fit fetch
/// and the Reed-Solomon solve are now load-bearing. Do NOT relax the
/// rebuilt-count assertion to a bare `repair complete`, and do not put
/// `payload` back.
#[tokio::test(flavor = "multi_thread")]
async fn an_obfuscated_post_repairs_from_its_own_unnamed_par2() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("obfpar2");
    let data = payloads::unique_payload(1_200_000, 0x5b17_0033);
    // Payload obfuscated too - hash subject AND hash yEnc name - so the
    // repair has to adopt it by content hash, not by its name.
    fx.add_file_obfuscated("Lp3vWq8xNc2", "Lp3vWq8xNc2", &data, 40_000);
    assert!(fx.add_par2_obfuscated(30, &["Lp3vWq8xNc2"], 40_000));
    assert!(
        !fx.nzb_files.iter().any(|(n, _)| n.contains(".par2")),
        "the test is void if any subject says par2"
    );

    // Drop three payload articles: real holes, well inside 30% recovery.
    let mut victims: Vec<String> = fx
        .articles
        .keys()
        .filter(|k| k.contains("Lp3vWq8xNc2"))
        .cloned()
        .collect();
    victims.sort();
    victims.truncate(3);
    assert_eq!(victims.len(), 3, "expected payload articles to drop");
    let chaos = Chaos {
        missing: victims.into_iter().collect(),
        ..Default::default()
    };

    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || run_get(&cfg, &nzb, &out, &[])
    })
    .await
    .unwrap();

    assert!(ok, "get failed on a repairable obfuscated post:\n{log}");
    // The recovery set did the whole repair: 200 holed blocks solved
    // from parity, nothing adopted. See this suite's generator note -
    // on `super::payload` this read `0 block(s) rebuilt ... 200 block(s)
    // adopted` and the recovery data was never consulted.
    assert!(
        log.contains("200 block(s) rebuilt") && !log.contains("block(s) adopted from"),
        "the sniffed set's parity did not solve the holes - the repair \
         found them somewhere else:\n{log}"
    );
    assert!(
        log.contains("recovery volume identified in-stream"),
        "the magic sniff never reclassified a volume:\n{log}"
    );
    assert!(
        log.contains("[par2] set live"),
        "the sniffed set never activated in-stream:\n{log}"
    );
    // The payload is back, byte-exact, under the name PAR2 knows it by.
    let repaired = std::fs::read(out.join("Lp3vWq8xNc2"))
        .unwrap_or_else(|e| panic!("payload missing from {}: {e}\n{log}", out.display()));
    assert_eq!(
        repaired.len(),
        data.len(),
        "wrong length after repair\n{log}"
    );
    assert!(
        repaired == data,
        "payload not byte-exact after repair\n{log}"
    );
}

/// Issue #9's SECOND half: a verified repair that left the folder holding
/// two copies of an 8.2 GB film.
///
/// The test above posts its payload under the same name the PAR2 set
/// gives it, so the repair patches one file and no duplicate is possible.
/// Here the set covers `Real.Movie.2026.mkv` while the post ships those
/// bytes as `g5lNXo3O7CTT6VS` - the reporter's actual shape. The download
/// lands as the hash, the adoption scan matches it by content, and the
/// repair writes the real name out beside it. The engine will not delete
/// the source (it does not own the directory) and the job tail sweeps by
/// extension, which a hash name has none of, so both copies survived -
/// along with the spent recovery volumes, themselves extensionless.
#[tokio::test(flavor = "multi_thread")]
async fn a_repaired_obfuscated_post_leaves_only_the_restored_payload() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("obfpar2dup");
    let data = payloads::unique_payload(1_200_000, 0x5b17_0035);
    fx.add_file_renamed_by_par2("Real.Movie.2026.mkv", "g5lNXo3O7CTT6VS", &data, 40_000);
    // A companion that keeps its real name, as a real release has. It is
    // what makes `repair_present_sets` recognise the set as present at
    // all: that test asks whether any FileDesc name is on disk, and on a
    // wholly renamed post the answer is no and the set is skipped.
    let nfo = payloads::unique_payload(4_000, 0x5b17_0036);
    fx.add_file("Real.Movie.2026.nfo", &nfo, 40_000);
    assert!(fx.add_par2_obfuscated(30, &["Real.Movie.2026.mkv", "Real.Movie.2026.nfo"], 40_000));
    assert!(
        !fx.nzb_files.iter().any(|(n, _)| n.contains(".par2")),
        "the test is void if any subject says par2"
    );

    // Real holes in the payload, well inside 30% recovery.
    let mut victims: Vec<String> = fx
        .articles
        .keys()
        .filter(|k| k.contains("g5lNXo3O7CTT6VS"))
        .cloned()
        .collect();
    victims.sort();
    victims.truncate(3);
    assert_eq!(victims.len(), 3, "expected payload articles to drop");
    let chaos = Chaos {
        missing: victims.into_iter().collect(),
        ..Default::default()
    };

    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || run_get(&cfg, &nzb, &out, &[])
    })
    .await
    .unwrap();

    assert!(ok, "get failed on a repairable obfuscated post:\n{log}");
    // The recovery set did the whole repair: 199 holed blocks solved
    // from parity, nothing adopted. See this suite's generator note -
    // on `super::payload` this read `0 block(s) rebuilt ... 199 block(s)
    // adopted` and the recovery data was never consulted.
    assert!(
        log.contains("199 block(s) rebuilt") && !log.contains("block(s) adopted from"),
        "the sniffed set's parity did not solve the holes - the repair \
         found them somewhere else:\n{log}"
    );
    // The cleanup is what removed them, not some earlier sweep that
    // happened to catch the same files - the end-state assertion below
    // cannot tell those apart on its own.
    assert!(
        log.contains("cleaned up") && log.contains("obfuscated leftover"),
        "the consumed-source cleanup never ran:\n{log}"
    );
    // The payload is back under the name PAR2 knows it by, byte-exact.
    let repaired = std::fs::read(out.join("Real.Movie.2026.mkv"))
        .unwrap_or_else(|e| panic!("payload missing from {}: {e}\n{log}", out.display()));
    assert!(
        repaired == data,
        "payload not byte-exact after repair\n{log}"
    );

    // ...and it is the ONLY thing left. Both the obfuscated original the
    // repair superseded (it donated nothing once the payload stopped
    // being self-similar - see the generator note above) and the spent
    // recovery volumes are gone.
    let mut left: Vec<String> = std::fs::read_dir(&out)
        .unwrap()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    left.sort();
    assert_eq!(
        left,
        vec![
            "Real.Movie.2026.mkv".to_string(),
            "Real.Movie.2026.nfo".to_string()
        ],
        "completed dir should hold only the recovery set's own files, found {left:?}\n{log}"
    );
}

/// The WHOLLY renamed post: one file, and not even a companion .nfo
/// keeps its real name, so not a single FileDesc name is on disk.
///
/// `repair_present_sets` used to decide presence purely by name and
/// skipped the set - a complete recovery set sitting right there, and
/// the job died as unrepairable. The name test coming up empty IS the
/// expected state on this shape; only the adoption scan's content match
/// can tie the hash on disk to the FileDesc. The presence gate now falls
/// back to attempting the sets when no name matched at all (and the
/// directory holds candidate files), letting the verdicts speak.
#[tokio::test(flavor = "multi_thread")]
async fn a_wholly_renamed_post_still_repairs_and_cleans_up() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("obfpar2whole");
    let data = payloads::unique_payload(1_200_000, 0x5b17_0037);
    fx.add_file_renamed_by_par2("Real.Movie.2026.mkv", "g5lNXo3O7CTT6VS", &data, 40_000);
    assert!(fx.add_par2_obfuscated(30, &["Real.Movie.2026.mkv"], 40_000));
    assert!(
        !fx.nzb_files.iter().any(|(n, _)| n.contains(".par2")),
        "the test is void if any subject says par2"
    );

    let mut victims: Vec<String> = fx
        .articles
        .keys()
        .filter(|k| k.contains("g5lNXo3O7CTT6VS"))
        .cloned()
        .collect();
    victims.sort();
    victims.truncate(3);
    assert_eq!(victims.len(), 3, "expected payload articles to drop");
    let chaos = Chaos {
        missing: victims.into_iter().collect(),
        ..Default::default()
    };

    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || run_get(&cfg, &nzb, &out, &[])
    })
    .await
    .unwrap();

    assert!(ok, "get failed on a wholly renamed repairable post:\n{log}");
    // The recovery set did the whole repair: 200 holed blocks solved
    // from parity, nothing adopted. See this suite's generator note -
    // on `super::payload` this read `0 block(s) rebuilt ... 200 block(s)
    // adopted` and the recovery data was never consulted.
    assert!(
        log.contains("200 block(s) rebuilt") && !log.contains("block(s) adopted from"),
        "the sniffed set's parity did not solve the holes - the repair \
         found them somewhere else:\n{log}"
    );
    let repaired = std::fs::read(out.join("Real.Movie.2026.mkv"))
        .unwrap_or_else(|e| panic!("payload missing from {}: {e}\n{log}", out.display()));
    assert!(
        repaired == data,
        "payload not byte-exact after repair\n{log}"
    );
    let mut left: Vec<String> = std::fs::read_dir(&out)
        .unwrap()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    left.sort();
    assert_eq!(
        left,
        vec!["Real.Movie.2026.mkv".to_string()],
        "completed dir should hold only the restored payload, found {left:?}\n{log}"
    );
}

/// A recovery set proves the files it covers and nothing else - the
/// invariant both repair arms spell out. Since issue #14 this obfuscated
/// shape activates its set in-stream (the disk-side fallback used to own
/// it), and the clean-set branch must apply the same coverage test.
///
/// This post carries one file OUTSIDE the set (a `.nfo`, the everyday
/// shape) whose every article 430s, next to a payload the obfuscated
/// recovery set covers completely. The set therefore verifies clean - a
/// verdict about the set, not about the job.
///
/// **This test used to assert the job FAILED, and issue #23 is why it no
/// longer does.** The original reasoning was right about the hazard and
/// wrong about the remedy. Filing such a job Completed used to hand an
/// *arr a directory containing a zero-filled hole that looks like a real
/// .nfo - genuinely worse than failing. But failing meant every download
/// the reporter attempted died over one absent article in a file their
/// own cleanup settings would have deleted seconds later, with no history
/// row for the *arr to read, an endless 20-minute retry for an article no
/// server has, and a good release reported to the indexer as dead.
///
/// The answer neither position reached: complete the job AND REMOVE the
/// partial file. Nothing can rebuild it (the set does not cover it) and
/// it is furniture rather than payload, so there is nothing to keep - and
/// with it gone, the hazard this test was written to catch cannot happen.
/// What must still hold, and is asserted below, is that the file is NAMED
/// and does not survive as a holed copy.
///
/// The failure summary must also not claim the post "carries no PAR2
/// recovery data" - it demonstrably does; it just cannot speak for the
/// .nfo. That half is unchanged.
#[tokio::test(flavor = "multi_thread")]
async fn a_disk_repair_does_not_certify_files_outside_its_recovery_set() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("obfpar2nfo");
    let data = payload(1_200_000, 34);
    fx.add_file_obfuscated("Rt9bKe4mZp1", "Rt9bKe4mZp1", &data, 40_000);
    // One article, entirely outside the recovery set below.
    fx.add_file("release.nfo", &payload(5_000, 91), 40_000);
    assert!(fx.add_par2_obfuscated(30, &["Rt9bKe4mZp1"], 40_000));

    // Every article of the .nfo is gone; the payload arrives whole, so
    // the recovery set has nothing to repair and verifies on disk.
    let victims: Vec<String> = fx
        .articles
        .keys()
        .filter(|k| k.contains("release_nfo"))
        .cloned()
        .collect();
    assert_eq!(victims.len(), 1, "expected the .nfo to be one article");
    let chaos = Chaos {
        missing: victims.into_iter().collect(),
        ..Default::default()
    };

    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || run_get(&cfg, &nzb, &out, &[])
    })
    .await
    .unwrap();

    assert!(
        log.contains("[par2] set live"),
        "the sniffed recovery set never activated, so this pins nothing:\n{log}"
    );
    // #23: furniture the set cannot cover no longer fails the job...
    assert!(
        ok,
        "a missing .nfo outside the set still failed the job (#23):\n{log}"
    );
    // ...but it is named, both where it went short and in the closing line.
    assert!(
        log.contains("release.nfo"),
        "the uncovered file was never named in the log:\n{log}"
    );
    assert!(
        log.contains("metadata file(s) no server had"),
        "the job completed silently about what it completed without:\n{log}"
    );
    assert!(
        !log.contains("carries no PAR2 recovery data"),
        "the summary lies about a post whose recovery set was sniffed:\n{log}"
    );
    // The hazard the original test existed for: a holed .nfo handed to an
    // *arr is worse than no .nfo. It must not be on disk at all.
    assert!(
        !out.join("release.nfo").exists(),
        "a partial .nfo was left in the completed directory:\n{log}"
    );
    // The payload the set DOES cover is whole and present.
    assert!(
        out.join("Rt9bKe4mZp1").exists() || std::fs::read_dir(&out).unwrap().flatten().count() > 0,
        "the completed directory is empty:\n{log}"
    );
}

/// Issue #14 on resume: a journal-completed head article never re-decodes,
/// so the live sniff cannot fire for it on run 2 - the resume path must
/// instead recognise restored recovery volumes by reading their first
/// bytes off disk, and defer their unfetched articles at build time.
/// Without that, every crash-resume of an obfuscated post refetched the
/// whole recovery set eagerly.
#[tokio::test(flavor = "multi_thread")]
async fn kill9_resume_of_an_obfuscated_post_still_defers_recovery_volumes() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("obfresume");
    // Payload dominant over the recovery set, for the same reason as the
    // sibling defer test: run 2's cancels are issued from the decode side
    // while the fetcher walks the queue, and the payload is the whole
    // cushion between them. An inverted ratio here let volumes sniffed
    // last (8, 9) have their bodies fetched before the cancel landed -
    // a SECOND, independent cause in this test, distinct from the
    // bootstrap-identity bug the assertion below fixes.
    let data = payload(12_000_000, 36);
    fx.add_file_obfuscated("Zx8pWn3kRf6", "Zx8pWn3kRf6", &data, 40_000);
    assert!(fx.add_par2_obfuscated(30, &["Zx8pWn3kRf6"], 40_000));
    let srv = MockServer::start(
        fx.articles.clone(),
        Chaos {
            delay_ms: 10,
            ..Chaos::default()
        },
    )
    .await;
    let served = srv.served.clone();
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    // Run 1: kill -9 once every head has been served and journaled (heads
    // go first in the queue; ~12 files here) plus some payload. The live
    // sniff already cancels the volume bodies in run 1, so a plain
    // fraction-of-total threshold would never be reached - the threshold
    // is heads + a margin instead.
    {
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        let served = served.clone();
        tokio::task::spawn_blocking(move || {
            let run = run_get_spawn(&cfg, &nzb, &out, &[], &[], 2, 1);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            let journal = out.join(".nzbfast.journal");
            while served.load(std::sync::atomic::Ordering::Relaxed) < 20
                || !std::fs::read_to_string(&journal).is_ok_and(|s| s.lines().count() > 12)
            {
                if std::time::Instant::now() > deadline {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            run.kill9();
        })
        .await
        .unwrap();
    }
    let bodies_before_run2 = srv.body_log.lock().unwrap().len();

    // Run 2: resume, recognise the restored volume partials by content,
    // finish clean - and fetch no recovery volume body.
    let (log, ok) = {
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
            .await
            .unwrap()
    };
    assert!(ok, "resume of a clean obfuscated post failed:\n{log}");
    assert!(
        log.contains("article(s) already on disk"),
        "no resume banner:\n{log}"
    );
    assert!(
        log.contains("recovery volumes by content"),
        "the resume-side disk sniff never recognised the restored volumes:\n{log}"
    );
    // Run 2's requests: volume heads not served before the kill may fetch
    // (part 1, and they live-sniff as in a fresh run) - and a volume
    // elected bootstrap has its articles promoted and downloads to
    // activate the set. Which one that is depends on how far run 1 got:
    // restored volumes are deferred at build time and cannot be
    // candidates, so the election takes the smallest volume still live.
    // Under load run 1 serves more, restores more, and the winner moves
    // off obf-par2-0 - reading it back from the banner is what keeps this
    // assertion about deferral instead of about where the kill landed.
    let elected = elected_bootstraps(&log);
    let run2: Vec<String> = srv.body_log.lock().unwrap()[bodies_before_run2..].to_vec();
    let vol_bodies: Vec<&String> = run2
        .iter()
        .filter(|id| {
            id.contains("obf-par2-")
                && !id.ends_with("-1@mock>")
                && !elected.iter().any(|p| id.starts_with(p))
        })
        .collect();
    assert!(
        vol_bodies.is_empty(),
        "resume refetched recovery volume bodies: {vol_bodies:?}\n{log}"
    );
    let got = std::fs::read(out.join("Zx8pWn3kRf6"))
        .unwrap_or_else(|e| panic!("payload missing from {}: {e}\n{log}", out.display()));
    assert!(got == data, "payload not byte-exact after resume\n{log}");
}

/// Issue #14, the deferral half: an UNDAMAGED fully obfuscated post must
/// not download its recovery set.
///
/// Every file's offset-0 article is fetched early by design; a head that
/// decodes to `PAR2\0PKT` reclassifies its slot in-stream. The smallest
/// sniffed file (here the index, which carries only critical packets)
/// becomes the bootstrap and activates the set; every other sniffed
/// volume has its still-queued articles cancelled. With nothing damaged,
/// the recovery data is never needed - so the mock's request log must
/// show ONLY head articles for the sniffed files, and the finished
/// directory holds nothing but the payload.
///
/// window=1 plus a small per-article delay keeps dispatch close to queue
/// order, so the volume bodies (queued after the whole payload) cannot
/// race ahead of the cancels.
///
/// The payload is deliberately an order of magnitude larger than the
/// recovery set, because the cancel is issued from the DECODE stage while
/// the FETCH stage runs ahead of it independently: a volume body the
/// fetcher dispatches before that volume's head finishes decoding is
/// downloaded despite the deferral. The size ratio is what bounds that
/// window - the fetcher has to chew through the whole payload before it
/// reaches any volume body, which is minutes on a real r5-r10 post over
/// GB of payload. An earlier 1.2 MB payload against a ~2.1 MB r30
/// recovery set inverted that ratio, left a window of tens of ms, and
/// lost the race under machine load (11/72 runs at load ~200 on 32
/// cores, once dropping the saving from 1.9 MB to 0.4 MB). Keep the
/// payload dominant: it is what makes this assertion about deferral
/// rather than about decoder scheduling.
///
/// The ratio is a cushion, not a proof - it still lost 1 run in 224 at
/// 28-way concurrent copies of this test. What closes the race is the
/// mock's `pause` gate below: once every offset-0 head has been
/// REQUESTED, the mock freezes, the decode side sniffs and cancels
/// against a world that cannot move, and only then does the fetcher get
/// to walk on. Under the freeze, waiting longer is free, so the drain
/// only has to beat scheduler starvation - never the fetcher.
#[tokio::test(flavor = "multi_thread")]
async fn an_undamaged_obfuscated_post_defers_its_sniffed_recovery_volumes() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("obfdefer");
    let data = payload(12_000_000, 35);
    fx.add_file_obfuscated("Vv2mQd7hLs4", "Vv2mQd7hLs4", &data, 40_000);
    assert!(fx.add_par2_obfuscated(30, &["Vv2mQd7hLs4"], 40_000));
    assert!(
        !fx.nzb_files.iter().any(|(n, _)| n.contains(".par2")),
        "the test is void if any subject says par2"
    );
    // The recovery set must be big enough that "deferred" is measurable:
    // at least one sniffed file with a body beyond its head article.
    assert!(
        fx.articles
            .keys()
            .any(|k| k.contains("obf-par2") && k.contains("-2@mock")),
        "fixture too small - every recovery file fits one article"
    );

    let chaos = Chaos {
        delay_ms: 2,
        ..Default::default()
    };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    // The determinism gate. Every file's offset-0 head is queued ahead of
    // all data bodies, and the mock logs a BODY command when it READS it,
    // before serving - so "all heads logged" means every head response is
    // either written or committed to be written in full (`pause` gates the
    // next read, never an in-flight response). Freeze there, wait for the
    // in-flight tail to quiesce on the frozen log, give the decode side a
    // generous drain to sniff all twelve heads and land every cancel
    // against an unmoving queue, then release. The CLI is a subprocess
    // behind `Command::output()`, so there is no live log to poll for a
    // deferral marker - the frozen fixed wait stands in for one, and it
    // is free precisely because the world is stopped.
    // body_log stores message-ids WITH angle brackets; the NZB segments
    // carry them bare.
    let heads: Vec<String> = fx
        .nzb_files
        .iter()
        .filter_map(|(_, segs)| segs.first().map(|(id, _, _)| format!("<{id}>")))
        .collect();
    let gate = {
        let pause = srv.pause.clone();
        let body_log = srv.body_log.clone();
        std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
            loop {
                let all_heads_logged = {
                    let log = body_log.lock().unwrap();
                    heads.iter().all(|h| log.contains(h))
                };
                if all_heads_logged {
                    break;
                }
                if std::time::Instant::now() > deadline {
                    // Never freeze a run that went sideways early; the
                    // assertions below still hold the line.
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            pause.store(true, std::sync::atomic::Ordering::Release);
            // A connection mid-read when the flag landed serves that one
            // command; wait until the frozen log stops moving.
            let mut last = usize::MAX;
            loop {
                let len = body_log.lock().unwrap().len();
                if len == last {
                    break;
                }
                last = len;
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            std::thread::sleep(std::time::Duration::from_millis(2000));
            pause.store(false, std::sync::atomic::Ordering::Release);
        })
    };
    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || run_get_win(&cfg, &nzb, &out, &[], &[], 1)
    })
    .await
    .unwrap();
    gate.join().unwrap();

    assert!(ok, "get failed on a clean obfuscated post:\n{log}");
    assert!(
        log.contains("recovery volume identified in-stream"),
        "the magic sniff never fired:\n{log}"
    );
    assert!(
        log.contains("[par2] set live"),
        "the sniffed set never activated in-stream:\n{log}"
    );
    assert!(
        log.contains("in-stream PAR2 identification deferred"),
        "nothing was deferred:\n{log}"
    );
    // The core claim: no deferred file's body was ever requested. Head
    // articles (part 1) are fetched early for every file by design, and
    // the bootstrap - the smallest sniffed file, deterministically the
    // index (obf-par2-0, critical packets only) - downloads in full to
    // activate the set. Everything else must appear as part-1 only.
    let requested: Vec<String> = srv
        .body_log
        .lock()
        .unwrap()
        .iter()
        .filter(|id| id.contains("obf-par2-"))
        .cloned()
        .collect();
    // The bootstrap is deterministically the index here (obf-par2-0,
    // critical packets only, so the smallest), but read it back rather
    // than hard-code it: the election switches if a smaller volume
    // sniffs while the current one is incomplete, and a demoted
    // bootstrap may already have fetched bodies off its promote. The
    // sibling resume test hit exactly that.
    let elected = elected_bootstraps(&log);
    let bodies: Vec<&String> = requested
        .iter()
        .filter(|id| !id.ends_with("-1@mock>") && !elected.iter().any(|p| id.starts_with(p)))
        .collect();
    assert!(
        bodies.is_empty(),
        "recovery-volume bodies were fetched despite deferral: {bodies:?}\n{log}"
    );
    // Payload intact, and the head-article partials cleaned up: nothing
    // but the payload (and no journal - the job succeeded) remains.
    let got = std::fs::read(out.join("Vv2mQd7hLs4"))
        .unwrap_or_else(|e| panic!("payload missing from {}: {e}\n{log}", out.display()));
    assert!(got == data, "payload not byte-exact\n{log}");
    let mut left: Vec<String> = std::fs::read_dir(&out)
        .unwrap()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    left.sort();
    assert_eq!(
        left,
        vec!["Vv2mQd7hLs4".to_string()],
        "completed dir should hold only the payload, found {left:?}\n{log}"
    );
}

/// Builds the issue-#14 reconcile fixture: an obfuscated post whose
/// set-covered payload is ITSELF a par2 file (a recovery volume of a
/// throwaway inner set), beside a normal movie payload, all covered by
/// an obfuscated outer recovery set. Returns (fixture, inner, movie).
fn par2_shaped_payload_fixture(tag: &str, salt: u8) -> (Fixture, Vec<u8>, Vec<u8>) {
    let mut fx = Fixture::new(tag);
    // The par2-shaped payload must span several articles, or deferral
    // has nothing to bite on.
    let inner: Vec<u8> = {
        std::fs::write(fx.dir.join("seed.bin"), payload(600_000, salt)).unwrap();
        let st = Command::new("par2")
            .arg("create")
            .arg("-r40")
            .arg("-q")
            .arg("innerset")
            .arg("seed.bin")
            .current_dir(&fx.dir)
            .status()
            .unwrap();
        assert!(st.success());
        // Largest inner par2 file = the fattest volume.
        let mut best: Option<(u64, PathBuf)> = None;
        for e in std::fs::read_dir(&fx.dir).unwrap().flatten() {
            let p = e.path();
            if p.extension().is_some_and(|x| x == "par2") {
                let len = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
                if best.as_ref().is_none_or(|(l, _)| len > *l) {
                    best = Some((len, p.clone()));
                }
            }
        }
        let (_, p) = best.expect("inner par2 created");
        let bytes = std::fs::read(&p).unwrap();
        // Scrub the workspace: the OUTER add_par2_obfuscated scans the
        // dir for *.par2 and would post the inner set otherwise.
        for e in std::fs::read_dir(&fx.dir).unwrap().flatten() {
            let p = e.path();
            if p.extension().is_some_and(|x| x == "par2") {
                std::fs::remove_file(&p).unwrap();
            }
        }
        std::fs::remove_file(fx.dir.join("seed.bin")).unwrap();
        bytes
    };
    assert!(
        inner.len() > 80_000,
        "inner par2 too small to span multiple articles ({} bytes)",
        inner.len()
    );
    let movie = payload(1_200_000, salt.wrapping_add(1));
    fx.add_file_obfuscated("Mm4kTq7wYz9", "Mm4kTq7wYz9", &movie, 40_000);
    fx.add_file_obfuscated("Pp6rLd2sVx8", "Pp6rLd2sVx8", &inner, 40_000);
    assert!(fx.add_par2_obfuscated(30, &["Mm4kTq7wYz9", "Pp6rLd2sVx8"], 40_000));
    (fx, inner, movie)
}

/// Issue #14 reconcile: an obfuscated post whose SET-COVERED PAYLOAD is
/// itself a par2 file. The content sniff cannot tell that file from a
/// recovery volume - both start with `PAR2\0PKT` - so it gets deferred.
/// Once the real set activates, its FileDesc table can: the deferred
/// slot's head fingerprint (md5-16k + length) matches a covered file, so
/// the run must un-defer it, verify it, and deliver it byte-exact -
/// never recreate it from recovery blocks, and never fail "unrepairable"
/// over a file that was fully fetchable. Unpaced, the tiny post drains
/// before activation, so this exercises the DRAIN fallback (side-fetch).
#[tokio::test(flavor = "multi_thread")]
async fn set_covered_payload_that_is_itself_par2_is_undeferred_and_delivered() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (fx, inner, movie) = par2_shaped_payload_fixture("obfpaypar", 40);
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || run_get(&cfg, &nzb, &out, &[])
    })
    .await
    .unwrap();

    assert!(ok, "a fully fetchable post failed:\n{log}");
    assert!(
        log.contains("is payload the recovery set covers"),
        "the reconcile pass never un-deferred the par2-shaped payload:\n{log}"
    );
    assert!(
        !log.contains("file missing entirely"),
        "the payload was treated as whole-file damage instead of fetched:\n{log}"
    );
    let got_inner = std::fs::read(out.join("Pp6rLd2sVx8"))
        .unwrap_or_else(|e| panic!("par2-shaped payload missing: {e}\n{log}"));
    assert!(
        got_inner == inner,
        "par2-shaped payload not byte-exact\n{log}"
    );
    let got_movie = std::fs::read(out.join("Mm4kTq7wYz9"))
        .unwrap_or_else(|e| panic!("movie payload missing: {e}\n{log}"));
    assert!(got_movie == movie, "movie payload not byte-exact\n{log}");
}

/// The same shape, PACED, so the pool is still running when the set
/// activates: the LIVE reconcile path must requeue the cancelled
/// articles into the running fetch ("resuming its download") instead of
/// waiting for the drain fallback.
#[tokio::test(flavor = "multi_thread")]
async fn live_reconcile_requeues_par2_shaped_payload_mid_download() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (fx, inner, movie) = par2_shaped_payload_fixture("obfpayparl", 44);
    let srv = MockServer::start(
        fx.articles.clone(),
        Chaos {
            delay_ms: 5,
            ..Chaos::default()
        },
    )
    .await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || run_get(&cfg, &nzb, &out, &[])
    })
    .await
    .unwrap();

    assert!(ok, "a fully fetchable post failed:\n{log}");
    assert!(
        log.contains("resuming its download"),
        "the live requeue path never fired (drain fallback only?):\n{log}"
    );
    let got_inner = std::fs::read(out.join("Pp6rLd2sVx8"))
        .unwrap_or_else(|e| panic!("par2-shaped payload missing: {e}\n{log}"));
    assert!(
        got_inner == inner,
        "par2-shaped payload not byte-exact\n{log}"
    );
    let got_movie = std::fs::read(out.join("Mm4kTq7wYz9"))
        .unwrap_or_else(|e| panic!("movie payload missing: {e}\n{log}"));
    assert!(got_movie == movie, "movie payload not byte-exact\n{log}");
}

/// Issue #14 hardening: a hole in the SNIFFED RECOVERY DATA must not fail
/// a job whose payload arrived perfectly. Here an article of the sniffed
/// bootstrap (the index, obf-par2-0) 430s on every server; the payload is
/// untouched. Recovery data is redundant by design - counting that hole
/// as "incomplete" failed a clean job that pre-#14 succeeded via the
/// disk arm. Whether activation survives the holed capture or falls back
/// to the no-set arm, the job must end Completed with the exact payload.
#[tokio::test(flavor = "multi_thread")]
async fn a_hole_in_the_sniffed_recovery_set_does_not_fail_a_clean_job() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("obfparhole");
    let data = payload(1_200_000, 37);
    fx.add_file_obfuscated("Gt5cRj9nXw2", "Gt5cRj9nXw2", &data, 40_000);
    assert!(fx.add_par2_obfuscated(30, &["Gt5cRj9nXw2"], 40_000));
    // The bootstrap is deterministically obf-par2-0 (the index, smallest
    // sniffed file). Kill its SECOND article: the head still sniffs, the
    // volume still elects, and the hole lands squarely in the bootstrap.
    let victim = "<obf-par2-0-2@mock>".to_string();
    assert!(
        fx.articles.contains_key(&victim),
        "fixture too small - the index fits one article, nothing to hole"
    );
    let chaos = Chaos {
        missing: [victim].into_iter().collect(),
        ..Default::default()
    };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || run_get(&cfg, &nzb, &out, &[])
    })
    .await
    .unwrap();

    assert!(
        ok,
        "a hole in redundant recovery data failed a clean job:\n{log}"
    );
    assert!(
        !log.contains("download incomplete"),
        "the recovery hole was misread as payload damage:\n{log}"
    );
    let got = std::fs::read(out.join("Gt5cRj9nXw2"))
        .unwrap_or_else(|e| panic!("payload missing from {}: {e}\n{log}", out.display()));
    assert!(got == data, "payload not byte-exact\n{log}");
}
