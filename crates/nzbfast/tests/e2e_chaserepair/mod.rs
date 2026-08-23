//! Shape-coverage row 26: a DAMAGED set that is being CHASED.
//!
//! Measured 22 Aug 2026 at **3.05x payload of device I/O** against
//! 1.03x for the same damage on a store set, because
//! `try_mapped_repair` declined a chased slot: the whole set
//! materialised, par2 repaired on disk, and unrar re-extracted it.
//! Design note `research/DESIGN-2026-08-22-row26-chase-repair.md`.
//!
//! DEFAULT ON since 22 Aug 2026, when the flip round re-measured the
//! same shape at **2.03x** of payload with the in-place route taken,
//! against 3.06x for the disk ladder on the same binary in the same
//! hour. The escape hatch is `NZBFAST_NO_CHASE_REPAIR=1`.
//!
//! The first leg and the last are the same fixture with the switch left
//! alone and thrown, and they are a PAIR on purpose - the thrown one is
//! what makes the default one mean anything, because "no materialize
//! line" is also what a test that never damaged anything prints.
//!
//! A sibling-dir child module (the `e2e_repair` pattern, harness
//! reached through `super::*`) so `e2e.rs` stays inside its size-gate
//! baseline.

use super::*;

/// The fixture every leg here runs: a compressed multi-volume RAR5 set
/// with one MID-SET article that never arrives, plus a 10% par2
/// sidecar.
///
/// Compressed (not store) is the whole point - a store set maps, and a
/// mapped slot has always taken the in-place patch. Level 1 because the
/// writer costs seconds per megabyte in a debug build and the fixture is
/// most of this leg's wall.
///
/// The victim is deliberately NOT in volume 1: the engine must have
/// decoded real bytes before it parks at the hole, or the leg would pass
/// on a chase that never started.
fn damaged_compressed_chase(tag: &str) -> (Fixture, Vec<u8>, Vec<String>) {
    let doc = half_entropy(24_000_000, 0x2545f4914f6cdd1d);
    let vols = rars::rar50::Rar50VolumeWriter::new(
        rars::rar50::WriterOptions::default().with_compression_level(1),
    )
    .compressed_entries(&[rars::rar50::CompressedEntry {
        name: b"movie.bin",
        data: &doc,
        mtime: None,
        attributes: 0,
        host_os: 0,
    }])
    .max_payload_per_volume(1_500_000)
    .finish()
    .unwrap();
    assert!(vols.len() >= 6, "want many volumes, got {}", vols.len());
    let mut fx = Fixture::new(tag);
    let names: Vec<String> = (1..=vols.len()).map(|i| format!("c.part{i}.rar")).collect();
    for (name, vol) in names.iter().zip(&vols) {
        fx.add_file(name, vol, 300_000);
    }
    let name_refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
    assert!(fx.add_par2(10, &name_refs, 300_000), "par2 create failed");
    (fx, doc, names)
}

/// One article of volume 4, past its head - the hole the decode parks
/// at. Refused forever by the mock, which is what a 430-everywhere post
/// looks like from here (and what `damage_nzb.py` builds for the bench
/// rig: it rewrites message-ids to ones no server has).
fn mid_set_victim(fx: &Fixture) -> String {
    fx.articles
        .keys()
        .find(|k| k.contains("c_part4_rar") && k.ends_with("-3@mock>"))
        .expect("volume 4 has a fourth article")
        .clone()
}

/// Run the mid-set-hole fixture: one article of volume 4 refused
/// forever, `env` on the job, `mem_limit` as the budget. Returns the
/// job log, its success, the original payload, the fixture and the
/// volume names.
///
/// Three legs share this because after the 22 Aug default flip they
/// differ only in `env` and the budget - a leg that had drifted a
/// fixture parameter away from its control would be comparing two
/// shapes and calling it a switch.
async fn damaged_chase_job(
    tag: &str,
    env: &'static [(&'static str, &'static str)],
    mem_limit: &'static str,
) -> (String, bool, Vec<u8>, Fixture, Vec<String>) {
    let (fx, doc, names) = damaged_compressed_chase(tag);
    let victim = mid_set_victim(&fx);
    let chaos = Chaos {
        missing: [victim].into(),
        ..Default::default()
    };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get_args(&cfg, &nzb, &out, env, &["--mem-limit", mem_limit])
    })
    .await
    .unwrap();
    (log, ok, doc, fx, names)
}

/// THE DEFAULT-ON PIN, and the leg the 22 Aug flip added: no
/// environment at all. The rebuilt blocks land in the chase's frontier
/// buffer, the parked decode resumes, and no volume ever becomes a
/// file - because that is what a stock binary now does, not because a
/// flag asked for it.
///
/// Before the flip this leg exported `NZBFAST_CHASE_REPAIR=1`. Passing
/// an empty `env` is the whole assertion: if the default ever went back
/// to dark, every one of the checks below fails, and the kill-switch
/// leg at the bottom of this file still passes, so the pair says which
/// way the default moved.
#[tokio::test(flavor = "multi_thread")]
async fn a_damaged_chase_repairs_in_place_and_stays_one_pass() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (log, ok, doc, fx, names) = damaged_chase_job("chase-repair-on", &[], "2G").await;
    assert!(ok, "job failed:\n{log}");
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.bin")).expect("extracted file"),
        doc,
        "extracted bytes differ"
    );
    // Teeth: the chase really ran, and the damage really was repaired.
    assert!(
        log.contains("extracting in-stream"),
        "the set never chased - the leg proves nothing:\n{log}"
    );
    assert!(
        log.contains("repair complete") && log.contains("(native, mapped"),
        "the hole was not repaired through the mapped path:\n{log}"
    );
    // The finding: none of the three-write route's footprints.
    assert!(
        !log.contains("materializing volumes for repair"),
        "the set fell off one-pass:\n{log}"
    );
    assert!(
        !log.contains("re-extracting") && !log.contains("native unpack complete"),
        "the archive was extracted a second time from disk:\n{log}"
    );
    for n in &names {
        assert!(
            !fx.dir.join("out").join(n).exists(),
            "volume {n} became a file:\n{log}"
        );
    }
    dump_route(&log);
}

/// The FIELD shape, and the reason the leg above is not enough: on the
/// 22 Aug bench the chase parked at its first hole in the opening
/// second and paged the whole 6.45 GB set to the holds scratch
/// (`🧊 archive decode blocked on missing articles`, leg log line 6 -
/// the stall window is clamped at 64 MB however large the budget is,
/// `chase_stall_spill`). So the bytes the rebuilt blocks have to join,
/// and the bytes the resumed decode then reads, are mostly NOT in RAM.
///
/// Budget picked so the set pages without ever breaching: the holds cap
/// is 45% of the memory budget floored at 64 MB, so `--mem-limit 8M`
/// gives ~28.8 MB of cap against a ~20 MB set - over the ~7.2 MB stall
/// window, under the cap. A trim would SPILL here rather than drop
/// (`lost_articles` is set), and a spilled prefix is a volume file,
/// which is exactly what the assertions below would catch.
#[tokio::test(flavor = "multi_thread")]
async fn a_paged_out_wedged_chase_repairs_in_place_too() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (log, ok, doc, fx, names) = damaged_chase_job("chase-repair-paged", &[], "8M").await;
    assert!(ok, "job failed:\n{log}");
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.bin")).expect("extracted file"),
        doc,
        "extracted bytes differ"
    );
    // Teeth: the wedge really did page, so the repair really did land
    // on a buffer whose bytes were mostly in the scratch file.
    assert!(
        log.contains("archive decode blocked on missing articles"),
        "the chase never paged - this leg is a duplicate of the one \
         above, not the field shape:\n{log}"
    );
    assert!(
        log.contains("repair complete") && log.contains("(native, mapped"),
        "the hole was not repaired through the mapped path:\n{log}"
    );
    assert!(
        !log.contains("materializing volumes for repair"),
        "the set fell off one-pass:\n{log}"
    );
    for n in &names {
        assert!(
            !fx.dir.join("out").join(n).exists(),
            "volume {n} became a file:\n{log}"
        );
    }
    dump_route(&log);
}

/// The poster-side fixture both verify-gate legs run: the LAST volume
/// re-encoded with 64 flipped bytes so every article CRC is valid for
/// the bytes it carries (the `e2e_drop` recipe). Early damage would
/// wedge nothing and simply fail the decode, which proves something
/// else. Returns the job log, its success, the original payload, the
/// fixture, the volume names, and every BODY message-id the mock
/// served in arrival order.
///
/// That last one is the independent witness for the fetch COUNT (23
/// Aug 2026): the job log says what the repair meant to do, the body
/// log says what actually came off the wire, and the defect this leg
/// now pins - a declined route buying its recovery a second time - is
/// invisible in bytes on a loopback rig and visible here as one
/// message-id served twice.
async fn poster_side_corrupted_job(
    tag: &str,
    verify_gate: &'static str,
) -> (String, bool, Vec<u8>, Fixture, Vec<String>, Vec<String>) {
    poster_side_corrupted_job_at(tag, verify_gate, &[(1, 2)]).await
}

/// [`poster_side_corrupted_job`] with the flipped runs placed by hand:
/// one 64-byte run at `len * n / d` for each `(n, d)`, so a caller can
/// damage a KNOWN number of distinct PAR2 blocks in the one chased
/// volume.
///
/// Returns what that one returns, body log included - it is this
/// function that runs the job, so the count witness has to come from
/// here rather than from the wrapper.
async fn poster_side_corrupted_job_at(
    tag: &str,
    verify_gate: &'static str,
    spots: &[(u64, u64)],
) -> (String, bool, Vec<u8>, Fixture, Vec<String>, Vec<String>) {
    let (mut fx, doc, names) = damaged_compressed_chase(tag);
    let victim = names.len() - 1;
    // `add_file` wrote each volume beside the NZB; that copy is the
    // source for the flipped re-post (the `e2e_drop` recipe).
    let good = std::fs::read(fx.dir.join(&names[victim])).expect("volume bytes");
    let mut bad = good.clone();
    for &(n, d) in spots {
        let at = (bad.len() as u64 * n / d) as usize;
        for b in &mut bad[at..at + 64] {
            *b ^= 0x5a;
        }
    }
    let tag = format!("{}-{}", names[victim].replace('.', "_"), victim);
    make_file_articles(&names[victim], &bad, 300_000, &tag, &mut fx.articles);
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get_args(
            &cfg,
            &nzb,
            &out,
            &[("NZBFAST_CHASE_VERIFY_GATE", verify_gate)],
            &["--mem-limit", "2G"],
        )
    })
    .await
    .unwrap();
    let bodies = srv.body_log.lock().expect("body log").clone();
    (log, ok, doc, fx, names, bodies)
}

/// The safety property, and the one case the in-place route must
/// REFUSE: poster-side corruption, §94 B's verify gate OFF. The bytes
/// arrive under a valid article CRC, so nothing on the download path
/// objects and the decode consumes them; only PAR2 knows, at settle,
/// and by then the rewrite would be correcting bytes the archive was
/// already decoded from.
///
/// Row 26's in-place repair is ON here, by default and not by flag.
/// The verdict must still be a decline (`chase_repair_conflicted`), the
/// set must materialize, and the output must be byte-exact - which is
/// what makes the three legs above a bet on the shape rather than on
/// the tripwire.
///
/// The verify gate is pinned OFF explicitly: with it on, the decode
/// never consumes an unverified block, the tripwire has nothing to
/// catch and the same damage repairs in place one-pass - the twin leg
/// below. Found by the gated e2e matrix on 22 Aug 2026, where this
/// leg's environment-inherited gate turned the decline into the
/// one-pass ending it was asserting against.
///
/// Since 23 Aug 2026 it also pins what the decline COSTS: the recovery
/// the mapped attempt had already bought is handed to the disk path
/// rather than dropped, so exactly one round of recovery articles
/// leaves the mock. See the body-log block at the end.
#[tokio::test(flavor = "multi_thread")]
async fn poster_side_corruption_still_declines_the_in_place_route() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (log, ok, doc, fx, names, bodies) =
        poster_side_corrupted_job("chase-repair-conflict", "0").await;
    assert!(ok, "job failed:\n{log}");
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.bin")).expect("extracted file"),
        doc,
        "extracted bytes differ - the decline did not rescue the output"
    );
    assert!(
        log.contains("mapped repair declined")
            && log.contains("the archive decode already consumed"),
        "the in-place route was taken on bytes the decode had consumed:\n{log}"
    );
    // The demote arrives through the TRIPWIRE, not through settle's
    // materialize loop: `chase_span` forfeits on the first differing
    // write, so by the time settle looks the slot is `RarFallback` and
    // its volumes are already files. Which is why `materializing
    // volumes for repair` is absent here and its absence means the
    // opposite of what it means in the three legs above - assert the
    // reason string instead, and the second extraction it leads to.
    assert!(
        log.contains("repair rewrote chased bytes"),
        "the conflict tripwire did not fire:\n{log}"
    );
    assert!(
        log.contains("native unpack complete"),
        "the materialized set was never unpacked:\n{log}"
    );
    // And the decline is FREE of recovery traffic beyond the one round
    // the damage actually needs (23 Aug 2026).
    //
    // The mapped route fetches before it can know its route survives,
    // so this leg's decline lands with the recovery already on disk;
    // until this was fixed, `fetch_and_repair` re-planned from scratch
    // and bought the identical volumes again. Measured on an M3 Ultra
    // (costB2 `loop-comp-silent`) as 134.6 MB where 67.3 MB was
    // needed, and worth nothing there because the round was LOOPBACK -
    // a second copy off 127.0.0.1 costs no wall and shows in no disk
    // column. On a provider it is metered traffic bought and thrown
    // away, on every damaged chased set that declines.
    //
    // Counted as ARTICLES, not bytes, and off the mock rather than off
    // our own log: a byte total is what the rig that missed this was
    // reading.
    let vol_bodies: Vec<&String> = bodies
        .iter()
        .filter(|id| id.contains("par2") && id.contains("_vol"))
        .collect();
    let mut seen: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for id in &vol_bodies {
        *seen.entry(id.as_str()).or_default() += 1;
    }
    let twice: Vec<(&str, usize)> = seen
        .iter()
        .filter(|&(_, &n)| n > 1)
        .map(|(&id, &n)| (id, n))
        .collect();
    assert!(
        twice.is_empty(),
        "{} recovery article(s) were fetched more than once - the declined \
         route bought its recovery twice: {twice:?}\n{log}",
        twice.len()
    );
    // Teeth for the count above: a leg that fetched NO recovery would
    // pass it vacuously, and this fixture's repair needs a block.
    assert!(
        !vol_bodies.is_empty(),
        "no recovery volume was fetched at all - the fetch count proves \
         nothing:\n{log}"
    );
    // And the reuse really is a reuse, not a fetch that happened to
    // dedup somewhere below us.
    assert_eq!(
        log.matches("→ fetching").count(),
        1,
        "expected exactly one recovery fetch round:\n{log}"
    );
    assert!(
        log.contains("already fetched before the in-place repair declined"),
        "the disk path re-planned instead of taking the banked volumes:\n{log}"
    );
    for n in &names {
        assert!(
            !fx.dir.join("out").join(n).exists(),
            "volume {n} survived the job:\n{log}"
        );
    }
    dump_route(&log);
}

/// The twin: the same poster-side damage with §94 B's verify gate ON.
/// The decode parks at the one block PAR2 will not vouch for, settle's
/// mapped repair rebuilds it into the frontier buffer, the decode
/// resumes, and no volume ever becomes a file: the tripwire never
/// fires because nothing it guards against can happen. This is the
/// ending the gate exists for ("damaged-and-ordinary sets stop
/// demoting", TODO 94 B), pinned here so the default flip has a test
/// that names it.
#[tokio::test(flavor = "multi_thread")]
async fn poster_side_corruption_repairs_in_place_under_the_verify_gate() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (log, ok, doc, fx, names, _bodies) =
        poster_side_corrupted_job("chase-repair-gated", "1").await;
    assert!(ok, "job failed:\n{log}");
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.bin")).expect("extracted file"),
        doc,
        "extracted bytes differ under the gate"
    );
    assert!(
        log.contains("rebuilt directly into the output"),
        "the repair did not land in place:\n{log}"
    );
    assert!(
        log.contains("volumes never touched disk"),
        "the gated chase did not stay one-pass:\n{log}"
    );
    assert!(
        !log.contains("repair rewrote chased bytes") && !log.contains("mapped repair declined"),
        "the tripwire fired under the gate - the decode consumed an unverified block:\n{log}"
    );
    for n in &names {
        assert!(
            !fx.dir.join("out").join(n).exists(),
            "volume {n} survived the job:\n{log}"
        );
    }
    dump_route(&log);
}

/// The route lines, to stderr, so a `--no-capture` run of these legs
/// reads like a bench leg log rather than a pass/fail.
fn dump_route(log: &str) {
    for l in log.lines().filter(|l| {
        l.starts_with("mem:")
            || l.contains("repair complete")
            || l.contains("materializing")
            || l.contains("archive:")
            || l.contains("paging to scratch")
            || l.contains("terminally missing")
            || l.contains("fetch")
    }) {
        eprintln!("  route| {l}");
    }
}

/// THE KILL-SWITCH PIN: `NZBFAST_NO_CHASE_REPAIR=1` and the same
/// fixture takes the measured 3x disk route again.
///
/// It has two jobs and both are load-bearing. It proves the escape
/// hatch works - the thing a user reaches for at 03:00 when the memory
/// price (784 -> 1213 MB peak RSS, measured 22 Aug) is the one that
/// matters on their box. And it is still the control for every leg
/// above: without a run of this fixture that DOES materialize, "no
/// materialize line" is also what a test that never damaged anything
/// prints.
///
/// Until 22 Aug 2026 this leg ran with no environment at all, because
/// no environment meant off. The flip moved the empty-env case up to
/// `a_damaged_chase_repairs_in_place_and_stays_one_pass`; this one now
/// names the switch explicitly.
#[tokio::test(flavor = "multi_thread")]
async fn the_same_damage_under_the_kill_switch_still_materializes() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (log, ok, doc, fx, _names) = damaged_chase_job(
        "chase-repair-off",
        &[("NZBFAST_NO_CHASE_REPAIR", "1")],
        "2G",
    )
    .await;
    assert!(ok, "job failed:\n{log}");
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.bin")).expect("extracted file"),
        doc,
        "extracted bytes differ"
    );
    assert!(
        log.contains("materializing volumes for repair"),
        "the kill switch did not disarm the in-place route, so the \
         default-on leg's absence of this line proves nothing:\n{log}"
    );
}

/// A DECLINED mapped repair still lands every block it rebuilt: three
/// bad blocks, one fixture, and both routes account for all three -
/// "mapped: 3" on the gated leg, and on the ungated one a decline whose
/// disk pass then finds NOTHING to do.
///
/// This leg was `the_two_routes_split_one_block_count_between_them`
/// until 23 Aug 2026, and its arithmetic was 3 = 1 + 2: the ungated
/// mapped attempt rebuilt into the frontier buffer, the FIRST of those
/// writes was the rewrite `chase_span` forfeits on, the slot became
/// `RarFallback` - and `patch_volume_span` refused that mode outright,
/// so the SECOND block's write returned "no backing data" and failed
/// the whole attempt. One block reached the buffer and materialized
/// with the volume; the other two were solved in memory and thrown
/// away, for the disk pass to fetch recovery for and solve again.
/// Seen on the bench with exactly those numbers (M3 Ultra, costB2
/// `loop-comp-silent`, 23 Aug 2026, 3 reps of 3 identical, at 35
/// blocks instead of 140).
///
/// `patch_volume_span` now admits `RarFallback` - the demote is
/// complete and synchronous by the time `chase_span` returns, so the
/// remaining blocks write through to the volume file that demote just
/// materialized. The tripwire is UNCHANGED and still fires: the decode
/// consumed stale bytes, so the set must re-extract off disk. What
/// changed is that the repair finishes first, so the route it declines
/// to reports "set already verifies on disk" instead of rebuilding two
/// blocks a second time. 3 = 3 + 0.
///
/// The counts still have to move TOGETHER, which is what the four
/// assertions below are for: the ledger must still name three, the
/// gated leg must still rebuild three, the ungated leg must reach the
/// disk pass with zero left, and it must get there through the
/// CONFLICT - a decline for any other reason (above all a return of
/// "no backing data") is a different leg making a claim this one is
/// not about.
#[tokio::test(flavor = "multi_thread")]
async fn a_declined_mapped_repair_still_lands_every_rebuilt_block() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    // Three 64-byte runs, a fifth of the volume apart, so each lands in
    // its own PAR2 block whatever block size par2 picked for the set.
    const SPOTS: &[(u64, u64)] = &[(1, 5), (1, 2), (4, 5)];
    let (gated, ok, doc, fx, _, _) =
        poster_side_corrupted_job_at("chase-repair-counts-gated", "1", SPOTS).await;
    assert!(ok, "gated job failed:\n{gated}");
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.bin")).expect("extracted file"),
        doc,
        "extracted bytes differ under the gate"
    );
    let (ungated, ok, doc, fx, _, _) =
        poster_side_corrupted_job_at("chase-repair-counts-ungated", "0", SPOTS).await;
    assert!(ok, "ungated job failed:\n{ungated}");
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.bin")).expect("extracted file"),
        doc,
        "extracted bytes differ on the disk route"
    );

    // The ledger both routes started from - the damage count settle
    // printed, and the number the two repair counts must split.
    for (leg, log) in [("gated", &gated), ("ungated", &ungated)] {
        assert_eq!(
            count_after(log, "blocks bad", " - "),
            Some(3),
            "the {leg} leg did not see the three damaged blocks - this \
             leg proves nothing about the two counts:\n{log}"
        );
    }
    assert_eq!(
        count_after(
            &gated,
            "block(s) rebuilt directly into the output",
            "mapped: "
        ),
        Some(3),
        "the mapped route no longer rebuilds every block the ledger \
         called bad:\n{gated}"
    );
    assert!(
        ungated.contains("set already verifies on disk"),
        "the disk route still had blocks to rebuild - the declined \
         mapped attempt did not land all three:\n{ungated}"
    );
    assert_eq!(
        count_after(&ungated, "block(s) rebuilt across", "in place: "),
        None,
        "the disk route printed an in-place count at all, so it \
         rebuilt blocks the mapped attempt had already solved:\n{ungated}"
    );
    // Teeth: without this the two assertions above also pass on a leg
    // whose mapped route SUCCEEDED and never declined at all, which
    // would mean the tripwire had stopped firing.
    assert!(
        ungated.contains("the archive decode already consumed"),
        "the ungated leg did not decline on the conflict, so its \
         clean disk pass proves nothing about the tripwire:\n{ungated}"
    );
    assert!(
        !ungated.contains("no backing data"),
        "a rebuilt block was still refused by the demoted slot:\n{ungated}"
    );
}

/// The integer a `[repair]`/`[verify]` sentence prints right after
/// `prefix`, on the line containing `marker`. Keyed on the prose either
/// side of the number rather than on a line position, so it fails
/// loudly (`None`) if a sentence is reworded rather than reading a
/// neighbouring count as if nothing had moved.
fn count_after(log: &str, marker: &str, prefix: &str) -> Option<usize> {
    let line = log.lines().find(|l| l.contains(marker))?;
    let rest = line.split(prefix).nth(1)?;
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}
