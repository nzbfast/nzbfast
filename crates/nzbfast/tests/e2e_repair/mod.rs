//! Repair-ladder e2e surfaces, a child module so e2e.rs stays inside
//! its size-gate baseline (the e2e_chip6 pattern: `mod` children in a
//! sibling dir, harness reached through `super::*`).

use super::*;
use crate::payloads;

/// Codex sweep 10 Aug M3: par2cmdline is an OPTIONAL escape hatch, so a
/// machine without one must still reach the escalation that fetches
/// every remaining recovery volume and retries natively. The old control
/// flow returned the moment the external binary would not spawn, which
/// put its own native escalation out of reach - a repairable set could
/// fail purely because an unrelated tool was not installed.
///
/// Both hatches are shut here: `PATH` is emptied so nothing resolves
/// `par2`, and the native kill switch makes every native attempt
/// decline. That pins the CONTROL FLOW - the escalation is entered and
/// the remaining volumes are fetched - not the repair verdict, which
/// cannot succeed with native repair switched off.
///
/// The `assert!(!ok)` at the bottom carries a SECOND pin nothing else
/// states: `rar_release`'s volumes carry neither a recovery record nor a
/// data CRC (`fixtures::rar5_volume_n`), so this is the shape the
/// `nothing_done` guard in `try_rar_rr_repair_hinted` exists for. Drop
/// that guard and the RR rung skips the volumes PAR2 vouched for, finds
/// no record in the damaged one, and hands an unchecked set to
/// `try_unrar` - which, with no CRC anywhere, extracts the holed bytes
/// as a success and greens this job. So do not switch this leg's fixture
/// to `rar5_volume_n_crc`: the missing CRC is what gives the assertion
/// its teeth.
#[tokio::test(flavor = "multi_thread")]
async fn a_missing_external_par2_still_reaches_the_native_escalation() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (fx, _inner, _vol_names) = rar_release("no-external-par2", true);
    let victim = |file: &str, suffix: &str| {
        fx.articles
            .keys()
            .find(|k| k.contains(file) && k.ends_with(suffix))
            .unwrap()
            .clone()
    };
    let chaos = Chaos {
        missing: [
            victim("r_part2_rar", "-3@mock>"),
            victim("r_part2_rar", "-5@mock>"),
        ]
        .into(),
        ..Default::default()
    };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || {
        // An empty PATH is the whole point: `tools::resolve("par2")`
        // falls back to the bare name, and with nothing to search the
        // spawn fails exactly as it does on a native-only install.
        run_get(
            &cfg,
            &nzb,
            &out,
            &[("PATH", ""), ("NZBFAST_NO_NATIVE_REPAIR", "1")],
        )
    })
    .await
    .unwrap();
    assert!(
        log.contains("no external par2 was runnable"),
        "the external hatch was not the one that closed:\n{log}"
    );
    assert!(
        log.contains("repair short - fetching all"),
        "a missing external par2 skipped the native escalation:\n{log}"
    );
    assert!(
        !ok,
        "with native repair switched off there is nothing left to repair with:\n{log}"
    );
}

/// Sweep 8 M1's production-route regression (TODO 199 item 7): a
/// recovery volume that lands PARTIAL must be refetched by the
/// escalation, not excluded from it forever.
///
/// `fetch_volumes` fetches a batch of chosen volumes, and the caller
/// recorded the whole batch in `fetched_files` - the escalation's
/// exclusion list - whatever actually landed. One lost article left its
/// volume short on disk and permanently ineligible: the escalation's
/// "fetch all remaining" skipped exactly the volume that was missing
/// slices, and a job with enough recovery in the post to repair was
/// declared unrepairable. The fix returns the failure count and clears
/// the batch on any failure, because the count cannot say WHICH volume
/// was short and only a complete volume may ever be excluded.
///
/// The oracle is the escalation's own traffic, read off the mock
/// server: the short volume's surviving articles are asked for a SECOND
/// time. Pre-fix they are asked exactly once and the volume stays
/// short. Both repair engines are shut off (native by switch, external
/// by an empty PATH) so the first pass is reliably short and the
/// escalation is reliably entered - this pins the CONTROL FLOW, not a
/// repair verdict, which is what the finding is about.
///
/// The shipped fix carried unit-level coverage only; this drives the
/// real orchestration through `run_get`.
#[tokio::test(flavor = "multi_thread")]
async fn a_partial_recovery_volume_is_refetched_by_the_escalation() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (fx, _inner, _vol_names) = rar_release("m1-partial-vol", true);
    let art = |needle: &str, suffix: &str| {
        fx.articles
            .keys()
            .find(|k| k.contains(needle) && k.ends_with(suffix))
            .unwrap_or_else(|| panic!("no article matching {needle}{suffix}"))
            .clone()
    };
    // Payload damage, so a repair is genuinely needed.
    let payload_gone = [
        art("r_part2_rar", "-3@mock>"),
        art("r_part2_rar", "-5@mock>"),
    ];
    // The BIGGEST recovery volume, which any minimal cover of a large
    // deficit selects - so the batch that comes back short is one the
    // first pass actually chose. One of its articles is lost.
    let stem: String = {
        let mut vols: Vec<&String> = fx
            .articles
            .keys()
            .filter(|k| k.contains("vol") && k.contains("par2"))
            .collect();
        vols.sort();
        let last = vols.last().expect("the fixture posts recovery volumes");
        last.rsplit_once('-')
            .expect("article ids end -N@mock>")
            .0
            .to_string()
    };
    let mut family: Vec<String> = fx
        .articles
        .keys()
        .filter(|k| k.starts_with(&stem))
        .cloned()
        .collect();
    family.sort();
    assert!(
        family.len() > 1,
        "the short volume must be multi-article for this rig to mean anything"
    );
    let short_article = family[0].clone();
    let siblings: Vec<String> = family[1..].to_vec();

    let mut missing: std::collections::HashSet<String> = payload_gone.into_iter().collect();
    missing.insert(short_article);
    let srv = MockServer::start(
        fx.articles.clone(),
        Chaos {
            missing,
            ..Default::default()
        },
    )
    .await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, _ok) = tokio::task::spawn_blocking(move || {
        run_get(
            &cfg,
            &nzb,
            &out,
            &[("PATH", ""), ("NZBFAST_NO_NATIVE_REPAIR", "1")],
        )
    })
    .await
    .unwrap();
    assert!(
        log.contains("repair short - fetching all"),
        "the escalation must be entered at all:\n{log}"
    );
    let served = srv.serve_counts();
    let counts: Vec<(String, u64)> = siblings
        .iter()
        .map(|id| (id.clone(), served.get(id).copied().unwrap_or(0)))
        .collect();
    assert!(
        counts.iter().any(|(_, n)| *n > 1),
        "the short recovery volume was never asked for again - it stayed on the \
         escalation's exclusion list, which is the finding. Its articles were \
         served {counts:?}\n{log}"
    );
}

/// The 11 Aug 2026 settle-round 3x-I/O shape (a big-RAM desktop
/// against five real backbones), rebuilt on loopback:
/// a damaged store set whose big middle volume delivers its offset-0
/// article LAST (synthesized segment numbering here; a refusal ladder
/// walking the head at provider latency does the same in the field).
/// The volume piles into pre-classification holds - and with gigabytes
/// of budget free it must HOLD, sniff on the late head, and let the
/// mapped repair patch the poisoned block straight into the output.
///
/// Before the budget-aware spill ceiling, this exact fixture spilled the
/// volume to Plain at a flat 64 MB, and a damaged-but-unmapped file
/// makes `try_mapped_repair` decline the WHOLE set: every volume
/// materialized for a disk-fed repair + re-extract - ~3x the payload in
/// disk traffic, at 96% free budget. The two log lines asserted absent
/// are that path's unavoidable footprints.
///
/// The holds-peak assertion is the fixture's teeth: it proves the head
/// really did run behind more bytes than the old flat ceiling, so a
/// scheduling change that quietly delivers the head early fails loudly
/// here instead of turning this into a test that passes either way.
#[tokio::test(flavor = "multi_thread")]
async fn a_late_head_on_a_damaged_volume_still_repairs_one_pass() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("late-head-onepass");
    let total: usize = 92 << 20;
    let inner = payload(total, 3);
    // Odd split points so no boundary aligns with articles or blocks.
    let v1end = (6 << 20) + 137;
    let v2end = (86 << 20) + 1234;
    let vols = [
        fixtures::rar5_volume_n(
            &[("movie.mkv", total as u64, &inner[..v1end], false, true)],
            0,
        ),
        fixtures::rar5_volume_n(
            &[("movie.mkv", total as u64, &inner[v1end..v2end], true, true)],
            1,
        ),
        fixtures::rar5_volume_n(
            &[("movie.mkv", total as u64, &inner[v2end..], true, false)],
            2,
        ),
    ];
    let names = ["r.part1.rar", "r.part2.rar", "r.part3.rar"];
    for (name, vol) in names.iter().zip(&vols) {
        fx.add_file(name, vol, 512_000);
    }
    // Reverse part2's LISTED order and renumber: the article carrying
    // offset 0 sits last in the queue, so ~80 MB of the volume arrives
    // before the sniff can run. Reversal (not rotation) on purpose -
    // the extractor's rotation probe would find a rotated head in one
    // promote, and then this test would exercise nothing.
    {
        let (_, segs) = fx
            .nzb_files
            .iter_mut()
            .find(|(n, _)| n == "r.part2.rar")
            .unwrap();
        segs.reverse();
        for (i, s) in segs.iter_mut().enumerate() {
            s.2 = (i + 1) as u32;
        }
    }
    assert!(fx.add_par2(10, &names, 512_000), "par2 create failed");
    // One poisoned mid-volume article: refused forever, repaired from
    // parity. Its id keeps the TRUE segment index (~offset 40 MB).
    let victim = fx
        .articles
        .keys()
        .find(|k| k.contains("r_part2_rar") && k.ends_with("-80@mock>"))
        .expect("victim article exists")
        .clone();
    let chaos = Chaos {
        missing: [victim].into(),
        ..Default::default()
    };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let expect = inner.clone();

    let (log, ok) = tokio::task::spawn_blocking(move || {
        // 2 GB budget: holds slice 900 MB, so the ~80 MB late volume
        // sits far inside it - the flat 64 MB ceiling is the only
        // thing that ever spilled here.
        run_get_args(&cfg, &nzb, &out, &[], &["--mem-limit", "2G"])
    })
    .await
    .unwrap();
    assert!(ok, "job failed:\n{log}");
    assert_eq!(
        std::fs::read(fx.dir.join("out").join("movie.mkv")).unwrap(),
        expect,
        "output differs"
    );
    assert!(
        log.contains("repair complete") && log.contains("(native, mapped"),
        "the poisoned block was not repaired through the mapping:\n{log}"
    );
    assert!(
        !log.contains("materializing volumes for repair"),
        "the set fell off one-pass - volumes materialized for a disk-fed \
         repair:\n{log}"
    );
    assert!(
        !log.contains("mapped repair declined"),
        "mapped repair declined:\n{log}"
    );
    // Teeth: the held window really did exceed the old flat ceiling.
    let holds_mb = log
        .lines()
        .find(|l| l.contains("holds peak"))
        .and_then(|l| l.split("holds peak").nth(1))
        .and_then(|t| t.trim().split(' ').next())
        .and_then(|n| n.parse::<f64>().ok())
        .expect("mem summary line present");
    assert!(
        holds_mb > 64.0,
        "fixture lost its teeth: holds peaked at {holds_mb} MB - the head \
         was not late enough to matter"
    );

    // Degradation leg, same fixture: on a genuinely small budget the
    // spill must fire exactly as before the budget-aware ceiling - the
    // volume goes to disk, the disk-fed repair takes over, and the job
    // still ends byte-correct. 100 MB budget → 45 MB holds slice →
    // 11.25 MB window, far under the ~80 MB the late head runs behind.
    //
    // It was 200 MB (a 90 MB slice) until the late-head grace landed:
    // the grace lets a slot still waiting for its offset-0 article hold
    // up to the WHOLE slice rather than a quarter of it, so an 80 MB
    // pile inside a 90 MB slice now rides the head out instead of
    // spilling. Halving the budget puts the volume back outside the
    // slice, which is the shape this leg was written to pin.
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out_small = fx.dir.join("out-small");
    let out_small2 = out_small.clone();
    let expect = inner;
    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get_args(&cfg, &nzb, &out_small2, &[], &["--mem-limit", "100M"])
    })
    .await
    .unwrap();
    assert!(ok, "small-budget job failed:\n{log}");
    assert!(
        log.contains("materializing volumes for repair"),
        "an 11 MB hold window rode out an 80 MB late head - the small-budget \
         spill stopped degrading:\n{log}"
    );
    assert_eq!(
        std::fs::read(out_small.join("movie.mkv")).unwrap(),
        expect,
        "small-budget output differs"
    );
}

/// TODO 160: the damage is in a PLAIN member of the recovery set, and
/// every archive volume beside it arrived perfectly. The plain file's
/// bad blocks must patch in place through its own writer, leaving the
/// store set exactly where it was - one-pass, no volume on disk.
///
/// Before the fix the mapped-repair gate refused any damaged slot that
/// was not `is_mapped`, so a single lost article in `notes.bin` declined
/// the WHOLE call: every volume materialized under its PAR2 name for a
/// disk-fed `repair_dir` and was then re-extracted from disk. That is
/// the §156.1 A/B's leg A2 shape (one fault in a plain file, a fully
/// intact 12-volume chase demoted with it), reduced to a store set so it
/// runs in seconds.
///
/// The teeth are the two output assertions TOGETHER with the absent
/// materialize line: `notes.bin` byte-correct proves the repair really
/// happened rather than the damage being waved through, and the volumes
/// missing from disk prove it happened on the mapped lane.
#[tokio::test(flavor = "multi_thread")]
async fn damage_in_a_plain_set_member_leaves_the_volumes_one_pass() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("plain-damage-onepass");
    let inner = payload(900_000, 7);
    let vols = [
        fixtures::rar5_volume_n(&[("movie.mkv", 900_000, &inner[..350_001], false, true)], 0),
        fixtures::rar5_volume_n(
            &[("movie.mkv", 900_000, &inner[350_001..700_001], true, true)],
            1,
        ),
        fixtures::rar5_volume_n(&[("movie.mkv", 900_000, &inner[700_001..], true, false)], 2),
    ];
    let vol_names = ["r.part1.rar", "r.part2.rar", "r.part3.rar"];
    for (name, vol) in vol_names.iter().zip(&vols) {
        fx.add_file(name, vol, 60_000);
    }
    // The plain member: ordinary bytes, no archive shape, so it sniffs
    // to a Plain slot and its output file IS the thing par2 covers.
    let notes = payload(600_000, 11);
    fx.add_file("notes.bin", &notes, 60_000);
    let covered = ["r.part1.rar", "r.part2.rar", "r.part3.rar", "notes.bin"];
    assert!(fx.add_par2(30, &covered, 60_000), "par2 create failed");

    // One article of the PLAIN file never arrives. Every volume is clean.
    let victim = fx
        .articles
        .keys()
        .find(|k| k.contains("notes_bin") && k.ends_with("-3@mock>"))
        .expect("victim article exists")
        .clone();
    let chaos = Chaos {
        missing: [victim].into(),
        ..Default::default()
    };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "job failed:\n{log}");
    assert!(
        log.contains("repair complete") && log.contains("(native, mapped"),
        "the plain file's damage did not repair through the mapping:\n{log}"
    );
    assert!(
        !log.contains("mapped repair declined"),
        "mapped repair declined:\n{log}"
    );
    assert!(
        !log.contains("materializing volumes for repair"),
        "damage in a plain member still demoted the archive set to \
         disk:\n{log}"
    );
    assert_eq!(
        std::fs::read(fx.dir.join("out").join("notes.bin")).unwrap(),
        notes,
        "the repaired plain file differs"
    );
    assert_eq!(
        std::fs::read(fx.dir.join("out").join("movie.mkv")).unwrap(),
        inner,
        "extracted bytes differ"
    );
    for v in &vol_names {
        assert!(
            !fx.dir.join("out").join(v).exists(),
            "volume {v} must not touch disk"
        );
    }
}

/// THE DAEMON'S TAIL ON THE SHAPE A USER NOTICES: a big member with one
/// bad article. The repair's self-prove hashes every rebuilt file end to
/// end against its FileDesc MD5, which is a serial 0.74 GB/s chain and
/// ~31 s on a 23 GB member - measured as `postproc_secs`. Since 2 Sep
/// 2026 the bytes BELOW the first hole are hashed off disk while the
/// download is still running (`nzbkit::live::prefix`, armed here by the
/// engine's first-lost-article gate) and the self-prove resumes there,
/// rereading that span against its IFSC CRC32s instead - 16x cheaper
/// through the same reader.
///
/// THE BOUND IS IN BYTES, NOT SECONDS, and deliberately: a wall-clock
/// assertion on a shared CI runner measures the runner. The bytes the
/// MD5 chain had to walk are a deterministic function of where the hole
/// is, and they are what the whole change moves - so the repair line
/// reports them and this row bounds them.
///
/// The damage is placed LATE on purpose. The saving IS the prefix, so a
/// hole a quarter of the way in can only ever buy a quarter, and a
/// fixture that hides that is a fixture that cannot fail when the
/// mechanism regresses to nothing (measured on
/// `par2_mapped_repair_bench`, 2 Sep 2026: first hole at 10/25/50/75/90%
/// bought 9/22/44/63/79% of the tail).
#[tokio::test(flavor = "multi_thread")]
async fn one_bad_article_late_in_a_member_keeps_the_selfprove_off_the_prefix() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("selfprove-prefix");
    // A plain member big enough for the split to be legible in the
    // report line's one decimal place, in 40 articles so the hole can
    // be placed at a percentage rather than at a boundary.
    const MEMBER: usize = 4_000_000;
    let notes = payload(MEMBER, 23);
    fx.add_file("notes.bin", &notes, 100_000);
    let filler = payload(400_000, 24);
    fx.add_file("other.bin", &filler, 100_000);
    let covered = ["notes.bin", "other.bin"];
    assert!(fx.add_par2(30, &covered, 100_000), "par2 create failed");

    // Article 35 of 40: ~85% of the way in, so the proven prefix is
    // most of the member and the MD5 chain is left with the rest.
    let victim = fx
        .articles
        .keys()
        .find(|k| k.contains("notes_bin") && k.ends_with("-35@mock>"))
        .expect("victim article exists")
        .clone();
    let chaos = Chaos {
        missing: [victim].into(),
        // A slow server, so the hasher has the ordinary thing it has on
        // a real job - wall clock between the loss being known and the
        // slot settling. Over loopback with no delay the whole download
        // is milliseconds and this row would be measuring the scheduler.
        delay_ms: 4,
        ..Default::default()
    };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "job failed:\n{log}");
    assert_eq!(
        std::fs::read(fx.dir.join("out").join("notes.bin")).unwrap(),
        notes,
        "the repaired member differs - the prefix arm must not change a byte"
    );
    assert!(
        log.contains("repair complete") && log.contains("(native, mapped"),
        "the damage did not repair through the mapping:\n{log}"
    );

    // `self-prove: X MiB hashed, Y MiB carried in from ...`
    let line = log
        .lines()
        .find(|l| l.contains("carried in from the download's prefix digest"))
        .unwrap_or_else(|| panic!("the self-prove reported no carried prefix at all:\n{log}"));
    let mib = |after: &str| -> f64 {
        let tail = line.split(after).nth(1).expect("report line shape");
        tail.trim()
            .split(' ')
            .next()
            .and_then(|n| n.parse::<f64>().ok())
            .unwrap_or_else(|| panic!("unparseable figure before {after}: {line}"))
    };
    let hashed = mib("self-prove: ");
    let carried = mib("MiB hashed, ");
    let member_mib = MEMBER as f64 / (1 << 20) as f64;
    assert!(
        carried > member_mib / 2.0,
        "the prefix carried {carried:.1} MiB of a {member_mib:.1} MiB member - \
         a hole at 85% should carry most of it: {line}"
    );
    assert!(
        hashed < member_mib / 2.0,
        "the self-prove still hashed {hashed:.1} MiB of a {member_mib:.1} MiB \
         member: {line}"
    );
}

/// TODO §282 item 15, at the surface the operator actually reads.
///
/// On a real daemon, 24 Aug 2026 00:36Z, a 1024 MB recovery fetch came
/// back with 68.9 MB and 1206 article failures and the decline read
/// `mapped repair declined (recovery set malformed: 0 recovery slice(s)
/// for 163 missing block(s))`. The set was not malformed. Every one of
/// its volumes was fine on the poster's side; the provider simply would
/// not serve them, and at a 5.25 MB block size across ~800 KB articles
/// not one slice landed whole. (Measured afterwards on the leftover
/// volumes: 0.9% to 5.5% of their bytes present, six torn RecvSlic
/// packets between them, zero valid ones - so the ZERO was arithmetic,
/// and only the word for it was wrong.)
///
/// This drives that exact shape: enough recovery declared in the NZB to
/// clear the mapped path's `have < needed` bail, and every recovery
/// VOLUME article dead, so the fetch returns nothing usable. The teeth
/// are the two clauses together - the verdict names a shortfall rather
/// than a malformed set, and it says the fetch is where the data went
/// missing, which is what tells the reader to look at the provider
/// instead of at the PAR2 parser.
#[tokio::test(flavor = "multi_thread")]
async fn an_unservable_recovery_set_declines_as_short_not_malformed() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("recovery-unservable");
    // The shared generator and not `payload`, resolving follow-up 13c.5
    // (31 Aug 2026). This row was never in the parity-budget class -
    // every one of its assertions is about the decline verdict and it
    // ignores the exit status on purpose - but on `payload` it went on
    // to complete `0 block(s) rebuilt, 600 block(s) adopted from
    // notes.bin` over a set whose every recovery volume 430s, which
    // reads alarming out of context. On bytes with no repeating block
    // the holes have no twin, so the decline is the run's real terminal
    // state rather than a decline followed by a coincidental self-heal -
    // which is closer to the incident this row reproduces, where the
    // payload served and the recovery did not.
    let notes = payloads::unique_payload(600_000, 23);
    fx.add_file("notes.bin", &notes, 60_000);
    assert!(
        fx.add_par2(50, &["notes.bin"], 60_000),
        "par2 create failed"
    );

    // Damage first: several payload articles gone, so the repair needs
    // more blocks than the bootstrap index alone can ever hold.
    let mut missing: std::collections::HashSet<String> = fx
        .articles
        .keys()
        .filter(|k| k.contains("notes_bin"))
        .filter(|k| {
            ["-2@mock>", "-4@mock>", "-6@mock>"]
                .iter()
                .any(|s| k.ends_with(s))
        })
        .cloned()
        .collect();
    assert!(
        !missing.is_empty(),
        "the fixture must post multi-article files"
    );
    // Then the recovery set itself: every VOLUME article 430s while the
    // index `.par2` still serves, which is the incident's shape - the
    // set is discovered and believed, and none of its slices can be had.
    let dead_volumes: Vec<String> = fx
        .articles
        .keys()
        .filter(|k| k.contains("vol") && k.contains("par2"))
        .cloned()
        .collect();
    assert!(
        !dead_volumes.is_empty(),
        "the fixture must post recovery volumes for this rig to mean anything"
    );
    missing.extend(dead_volumes);

    let srv = MockServer::start(
        fx.articles.clone(),
        Chaos {
            missing,
            ..Default::default()
        },
    )
    .await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, _ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();

    assert!(
        log.contains("mapped repair declined"),
        "the mapped lane never reached its shortfall verdict:\n{log}"
    );
    assert!(
        log.contains("recovery data short") && log.contains("usable recovery slice(s)"),
        "the verdict must name the shortfall:\n{log}"
    );
    assert!(
        !log.contains("recovery set malformed"),
        "an unservable recovery set is not a malformed one:\n{log}"
    );
    assert!(
        log.contains("the recovery fetch lost"),
        "the verdict must say the FETCH is where the recovery data went, \
         which is the whole difference between a bad post and a bad \
         provider:\n{log}"
    );
}

/// The §282 incident fixture: a post whose PAYLOAD serves and whose
/// RECOVERY VOLUMES do not.
///
/// `rar_release`'s own recovery set is posted in 60 kB articles, which
/// at this geometry is three or four articles for the whole set - below
/// `VolumeYield`'s sample floor, and rightly so: a ratio over four
/// articles is not evidence about a provider. So the recovery here goes
/// out in 2 kB articles, which is what a real 1.35 GB recovery set
/// looks like from the yield gate's point of view (the incident's fetch
/// asked for 1293 articles) without making the fixture big. The PAYLOAD
/// articles shrink too, for a different reason - see below.
///
/// The redundancy is the default 20%: what matters is that the damage
/// needs recovery, not how much of it there is.
fn recovery_starved_release(tag: &str) -> (Fixture, Vec<u8>) {
    let mut fx = Fixture::new(tag);
    let inner = payloads::unique_payload(900_000, 0x0000_0282);
    let vols = [
        fixtures::rar5_volume_n(&[("movie.mkv", 900_000, &inner[..350_001], false, true)], 0),
        fixtures::rar5_volume_n(
            &[("movie.mkv", 900_000, &inner[350_001..700_001], true, true)],
            1,
        ),
        fixtures::rar5_volume_n(&[("movie.mkv", 900_000, &inner[700_001..], true, false)], 2),
    ];
    let names = ["r.part1.rar", "r.part2.rar", "r.part3.rar"];
    // 12 kB payload articles rather than `rar_release`'s 60 kB, so that
    // losing two of them is ~2.5% of the post and not 12%. §282 item
    // 17's rung will not call the parity the casualty unless the
    // payload is PROVEN mostly intact (a twentieth or less short) - a
    // run that lost an eighth of its payload has no business being told
    // the payload was fine - and the incident's own loss was 0.21%.
    for (name, vol) in names.iter().zip(&vols) {
        fx.add_file(name, vol, 12_000);
    }
    // ...and 2 kB recovery articles, so the whole set is enough of them
    // for a yield RATIO to be evidence. See the fn doc.
    assert!(fx.add_par2(20, &names, 2_000), "par2 create failed");
    (fx, inner)
}

/// §282 item 4, end to end: a provider that will not serve this post's
/// recovery set must not be asked for MORE of it.
///
/// This is the live incident of 24 Aug 2026 shrunk to loopback. There,
/// a repair asked for 1024 MB of recovery, 68.9 MB arrived (6.7%, 1206
/// article failures), and the daemon's answer was to fetch all seven
/// remaining volumes - 2755 seconds of post-processing against a 743
/// second download, on a payload that was 99.8% intact. Here the
/// recovery volumes 430 outright and the payload is short two articles,
/// which is the same fact with the noise taken out.
///
/// Three things are pinned, and the NEGATIVE one is the finding:
///
/// - the escalation is REFUSED, so "repair short - fetching all" never
///   prints. That string is asserted PRESENT by the two legs above, on
///   fixtures whose recovery serves; between them they say the gate
///   fires on the shape it is for and on nothing else.
/// - the console names which of the post's two halves failed, in the
///   yield that proved it.
/// - the job FAILS, promptly, rather than grinding through every
///   remaining volume first.
///
/// - and the sentence the USER reads names the recovery set, not the
///   payload. On this shape - and on the incident's, which is why - the
///   payload is genuinely short too, so `finish_job` takes its
///   `download incomplete` arm, which outranks the repair-shortfall arm
///   and is right to: `fail_kind` classifies on the opening. §282 item
///   17 built the rung inside that arm and left
///   `LossCauses::recovery_unobtainable` as an explicit seam for this
///   item's verdict; `RepairShortfall::Unservable` is what now sets it,
///   and this assertion is the end-to-end proof that the two halves
///   meet. Without the seam the counters are all zero here BY
///   CONSTRUCTION - `get::plan` never puts a named `Par2Volume` in the
///   main plan, so every one of these failures happened in a
///   repair-side fetch with no `FileSlot` to charge.
///
/// The shortfall arm's own wording, for a job whose payload IS whole,
/// is exercised by `failure_arms_are_ranked` in get/tail.rs.
///
/// The par2 index itself keeps serving: without it the set never
/// activates and the job fails long before any of this.
#[tokio::test(flavor = "multi_thread")]
async fn a_recovery_set_the_source_will_not_serve_stops_the_escalation() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (fx, _inner) = recovery_starved_release("unservable-recovery");
    let art = |needle: &str, suffix: &str| {
        fx.articles
            .keys()
            .find(|k| k.contains(needle) && k.ends_with(suffix))
            .unwrap_or_else(|| panic!("no article matching {needle}{suffix}"))
            .clone()
    };
    // Every article of every recovery VOLUME is gone; the index is not
    // a volume and keeps serving.
    let mut missing: std::collections::HashSet<String> = fx
        .articles
        .keys()
        .filter(|k| k.contains("vol") && k.contains("par2"))
        .cloned()
        .collect();
    assert!(
        missing.len() >= 16,
        "the fixture must post enough recovery articles for a yield RATIO to be \
         evidence - got {}",
        missing.len()
    );
    // ...and the payload is short two articles, so a repair is needed.
    missing.insert(art("r_part2_rar", "-3@mock>"));
    missing.insert(art("r_part2_rar", "-5@mock>"));

    let srv = MockServer::start(
        fx.articles.clone(),
        Chaos {
            missing,
            ..Default::default()
        },
    )
    .await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();

    assert!(
        !ok,
        "a post with no obtainable recovery cannot succeed:\n{log}"
    );
    assert!(
        !log.contains("repair short - fetching all"),
        "the escalation asked a provider that had just refused this recovery set for \
         the rest of it - that is the whole finding:\n{log}"
    );
    assert!(
        log.contains("recovery unusable"),
        "nothing named the recovery set as the thing that failed:\n{log}"
    );
    assert!(
        log.contains("recovery article(s) arrived"),
        "the verdict must carry the yield that produced it:\n{log}"
    );
    assert!(
        log.contains("the recovery data is what failed, not the payload"),
        "the yield verdict never reached item 17's rung, so the user is still being \
         told a 99%-intact payload is the casualty:\n{log}"
    );
}

/// §282 item 16: `install par2cmdline` must not be the advice when
/// par2cmdline could not have helped.
///
/// On the incident the line above it read "native repair: 145 block(s)
/// damaged, only 0 recovery block(s) on disk". Reed-Solomon cannot
/// invent data, so the external binary would have failed on the same
/// arithmetic - and the message instead sent its reader off to ask why
/// nzbfast needs an external par2 at all. It does not: `par2repair` is
/// a complete in-process implementation and the external binary is a
/// correctness backstop for a native BUG plus the `MAX_REPAIR_DIM`
/// guard, neither of which is what a parity-less set hit.
///
/// Same fixture as the leg above, with `PATH` emptied so nothing
/// resolves `par2` - which is exactly the native-only install the
/// message is aimed at. Native repair is left ON here, unlike the two
/// legs at the top of this file: its Unrepairable verdict is the input
/// the message now switches on.
#[tokio::test(flavor = "multi_thread")]
async fn no_recovery_on_disk_does_not_advertise_par2cmdline() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (fx, _inner) = recovery_starved_release("no-recovery-no-advice");
    let art = |needle: &str, suffix: &str| {
        fx.articles
            .keys()
            .find(|k| k.contains(needle) && k.ends_with(suffix))
            .unwrap_or_else(|| panic!("no article matching {needle}{suffix}"))
            .clone()
    };
    let mut missing: std::collections::HashSet<String> = fx
        .articles
        .keys()
        .filter(|k| k.contains("vol") && k.contains("par2"))
        .cloned()
        .collect();
    missing.insert(art("r_part2_rar", "-3@mock>"));
    missing.insert(art("r_part2_rar", "-5@mock>"));

    let srv = MockServer::start(
        fx.articles.clone(),
        Chaos {
            missing,
            ..Default::default()
        },
    )
    .await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, _ok) =
        tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[("PATH", "")]))
            .await
            .unwrap();

    assert!(
        log.contains("recovery block(s) on disk"),
        "the native pass must have reached its Unrepairable verdict for this leg to \
         mean anything:\n{log}"
    );
    assert!(
        !log.contains("install par2cmdline"),
        "a set with no parity on disk was told to go and install a tool that would \
         have failed identically:\n{log}"
    );
    assert!(
        log.contains("could not have helped"),
        "the honest replacement message never printed:\n{log}"
    );
}

// Moved out of e2e.rs 30 Aug 2026, which was ONE line under its
// size-gate baseline when a `mod` declaration for a new child module
// took it over. This module's own header says what it is for - "a child
// module so e2e.rs stays inside its size-gate baseline" - and the gate's
// rule is that the numbers only go down, so the fix for a full e2e.rs is
// to move a subject out and never to raise the baseline. This test was
// the natural one to take: it is the offline CLI twin of the par-only
// reconstruction the async tests above cover, so it belongs with the
// repair ladder rather than in the file that holds the shared fixtures.

/// The CLI flow of the same par-only case: `nzbfast extract <dir>` on a
/// directory holding ONLY the par2 set (the data file deleted). The
/// offline pipeline must recreate the rar from recovery blocks and then
/// extract it. rc=0.
#[test]
fn extract_local_par_only_dir_recreates_and_extracts() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let dir = std::env::temp_dir().join(format!("nzbfast-e2e-paronly-cli-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let movie = payload(220_000, 73);
    let rar = fixtures::rar5_volume(&[("movie.mkv", 220_000, &movie, false, false)]);
    std::fs::write(dir.join("r.rar"), &rar).unwrap();
    let st = Command::new("par2")
        .arg("create")
        .arg("-s4096")
        .arg("-r100")
        .arg("-q")
        .arg("cliset")
        .arg("r.rar")
        .current_dir(&dir)
        .status()
        .expect("run par2");
    assert!(st.success(), "par2 create failed");
    std::fs::remove_file(dir.join("r.rar")).unwrap();

    let o = Command::new(env!("CARGO_BIN_EXE_nzbfast"))
        .env("NZBFAST_OPEN", "1")
        .arg("extract")
        .arg(&dir)
        .output()
        .expect("run nzbfast extract");
    // stdout/stderr are separate pipes with no shared clock - label the
    // seam so a bare join can't be misread as one chronology. Copy the
    // comment along with the string.
    let log = format!(
        "{}\n----- stderr (a SEPARATE stream: not in sequence with stdout above) -----\n{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(o.status.success(), "extract failed:\n{log}");
    assert_eq!(
        std::fs::read(dir.join("movie.mkv")).expect("payload extracted"),
        movie,
        "payload bytes differ after CLI reconstruction"
    );
}
