//! Repair-ladder e2e surfaces, a child module so e2e.rs stays inside
//! its size-gate baseline (the e2e_chip6 pattern: `mod` children in a
//! sibling dir, harness reached through `super::*`).

use super::*;

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
