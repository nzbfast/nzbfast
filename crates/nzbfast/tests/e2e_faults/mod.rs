//! The fault-injection matrix for difficult posts (TODO 283).
//!
//! Every shape here is seeded from live evidence - a §282 log line, an
//! existing memory, a documented trap - rather than invented, and every
//! one is stated in terms of a FILE ROLE (`nzbkit::faultplan`) rather
//! than a message-id census, so a shape stays true when the fixture
//! moves. The §282 incident that motivates the section was found by a
//! human downloading a film; none of the four defects it surfaced was
//! reachable by any of `Chaos`'s forty knobs, because all forty apply
//! by id or by connection and none of them knows what a file is.
//!
//! **A shape that PASSES is the point.** The value is the matrix being
//! complete, so a later change that breaks one says so on the push that
//! breaks it. Several of these pin behaviour that is CORRECT today and
//! nothing else asserts; a couple pin behaviour that §282 is about to
//! improve, and those say in their own doc comment what they assert
//! today and what will replace it.
//!
//! These are HEAVY: they run the real binary against real mock servers
//! and one of them deliberately pays a round-trip cost per refusal.
//! They live in the `e2e` target, which is build-gated behind
//! `heavy-tests` (§116b), runs in nightly rather than per-push, and is
//! serialized by the `e2e-serial` test group in `.config/nextest.toml`.

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use nzbkit::faultplan::{FaultPlan, Role};
use nzbkit::mock::{Chaos, MockServer, make_file_articles};

use super::{Fixture, have_par2, run_get};

/// One payload file of `blocks` blocks, covered by a PAR2 set of
/// EXACTLY `recovery` blocks. Returns the payload bytes, so a shape that
/// repairs can prove the OUTPUT is right rather than resting on an exit
/// status.
///
/// The geometry is the whole point and it is chosen so the arithmetic a
/// shape wants to state is the arithmetic the test can perform: the
/// article size equals the PAR2 block size, so article *i* of the
/// payload is block *i* of the set and "damage k articles" is "damage
/// exactly k blocks". Shape 4's boundary cases are unstatable without
/// that.
///
/// `par2 create -c<n>` fixes the recovery block count outright, where
/// `-r<pct>` leaves it to a percentage of a file size the test would
/// then have to model.
fn matrix_post(fx: &mut Fixture, blocks: usize, bs: usize, recovery: usize) -> Vec<u8> {
    matrix_post_vols(fx, blocks, bs, recovery, None)
}

/// [`matrix_post`] with the recovery set collapsed into `vols` volumes.
///
/// `Some(1)` puts every recovery block in ONE volume, which is what
/// shape 2 needs: a volume that arrives in PART is only expressible when
/// the part that arrives and the part that does not are inside the same
/// file.
fn matrix_post_vols(
    fx: &mut Fixture,
    blocks: usize,
    bs: usize,
    recovery: usize,
    vols: Option<usize>,
) -> Vec<u8> {
    matrix_post_art(fx, blocks, bs, recovery, vols, bs)
}

/// [`matrix_post_vols`] with the RECOVERY set's article size stated
/// separately from the payload's.
///
/// The two are the same everywhere else in this module and the reason
/// is written up on [`matrix_post`]: article size equal to PAR2 block
/// size is what makes "damage k articles" mean "damage exactly k
/// blocks", and every shape that states arithmetic depends on it. That
/// argument is about the PAYLOAD. Nothing about a recovery volume needs
/// its articles to be block-sized, and one shape needs them not to be -
/// see [`RECOVERY_YIELD_ART`].
fn matrix_post_art(
    fx: &mut Fixture,
    blocks: usize,
    bs: usize,
    recovery: usize,
    vols: Option<usize>,
    par2_art: usize,
) -> Vec<u8> {
    let data = unique_payload(blocks * bs, 0x5eed_0283);
    fx.add_file("payload.bin", &data, bs);
    assert!(
        par2_create_exact(fx, recovery, bs as u64, vols, &["payload.bin"], par2_art),
        "par2 create failed - callers must gate on have_par2()"
    );
    data
}

/// The article size a recovery set is posted at when a shape needs the
/// product to be able to MEASURE whether a source will serve it.
///
/// §282 item 4's yield gate is a ratio, and a ratio over a tiny sample
/// is noise: `sidefetch::MIN_RECOVERY_YIELD_SAMPLE` is 16 articles, on
/// the stated reasoning that one lost article of a two-article volume
/// is 50% and says nothing at all about the source. At one article per
/// 64 KiB block, an 8-block recovery set is about five articles per
/// fetch - under the floor, so the gate correctly declines to judge,
/// and a shape that means "this provider will not serve the parity"
/// cannot be written at that geometry no matter how much of it is
/// killed. 8 KiB puts the same set at tens of articles, which is the
/// side of the floor the live incident was on: it asked for 1024 MB of
/// volumes and counted 1206 article failures.
///
/// This is the fixture bending to the product's rule, not around it.
/// The floor is a real threshold in shipped code and a shape whose
/// sample is under it is testing the floor, not the gate.
const RECOVERY_YIELD_ART: usize = 8_192;

/// `Fixture::add_par2_opts` with the recovery BLOCK COUNT pinned rather
/// than a redundancy percentage.
///
/// A free function over `&mut Fixture` rather than a method on it: the
/// e2e fixture builder is edited by several lanes at once, and this
/// needs nothing from it that a child module cannot reach.
fn par2_create_exact(
    fx: &mut Fixture,
    blocks: usize,
    block_size: u64,
    vols: Option<usize>,
    files: &[&str],
    art_size: usize,
) -> bool {
    let mut cmd = Command::new("par2");
    cmd.arg("create")
        .arg(format!("-s{block_size}"))
        .arg(format!("-c{blocks}"));
    if let Some(n) = vols {
        cmd.arg(format!("-n{n}"));
    }
    let st = cmd
        .arg("-q")
        .arg("testset")
        .args(files)
        .current_dir(&fx.dir)
        .status();
    match st {
        Ok(s) if s.success() => {}
        _ => return false,
    }
    let mut par2s: Vec<PathBuf> = std::fs::read_dir(&fx.dir)
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            (p.extension().is_some_and(|x| x == "par2")).then_some(p)
        })
        .collect();
    par2s.sort();
    for p in par2s {
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        let data = std::fs::read(&p).unwrap();
        let tag = format!("{}-{}", name.replace('.', "_"), fx.nzb_files.len());
        let segs = make_file_articles(&name, &data, art_size, &tag, &mut fx.articles);
        fx.nzb_files.push((name, segs));
        std::fs::remove_file(&p).unwrap();
    }
    true
}

/// The fault plan for a fixture, resolved off the rows it already
/// carries.
fn plan(fx: &Fixture) -> FaultPlan {
    FaultPlan::from_segments(&fx.nzb_files)
}

/// Run one shape against a fleet of `n` identical servers and report
/// (log, success, wall).
///
/// Identical because a post is damaged on the WIRE, not per-account:
/// every server on one backbone holds the same holes. The partial-fleet
/// case - where one provider does hold what the others do not - is
/// [`run_shape_mixed`], and the difference between the two is shape 10.
async fn run_shape(fx: &Fixture, chaos: Chaos, n: usize) -> (String, bool, Duration) {
    run_shape_env(fx, chaos, n, &[]).await
}

/// [`run_shape`] with environment for the run.
///
/// `NZBFAST_STALL_ABORT_SECS` is the one every stall-shaped fault wants:
/// the deadlock watchdog's window is 180 s in production and the
/// override exists so a test does not have to wait it out.
async fn run_shape_env(
    fx: &Fixture,
    chaos: Chaos,
    n: usize,
    env: &[(&str, &str)],
) -> (String, bool, Duration) {
    let mut servers = Vec::new();
    for _ in 0..n {
        servers.push(MockServer::start(fx.articles.clone(), chaos.clone()).await);
    }
    let refs: Vec<&MockServer> = servers.iter().collect();
    finish(fx, &refs, env).await
}

/// A fleet where the FIRST server carries the fault and the rest are
/// healthy - the second-backbone case.
async fn run_shape_mixed(fx: &Fixture, chaos: Chaos, healthy: usize) -> (String, bool, Duration) {
    let mut servers = vec![MockServer::start(fx.articles.clone(), chaos).await];
    for _ in 0..healthy {
        servers.push(MockServer::start(fx.articles.clone(), Chaos::default()).await);
    }
    let refs: Vec<&MockServer> = servers.iter().collect();
    finish(fx, &refs, &[]).await
}

async fn finish(
    fx: &Fixture,
    servers: &[&MockServer],
    env: &[(&str, &str)],
) -> (String, bool, Duration) {
    let cfg = fx.write_config(servers);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let owned: Vec<(String, String)> = env
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let t0 = Instant::now();
    let (log, ok) = tokio::task::spawn_blocking(move || {
        let borrowed: Vec<(&str, &str)> = owned
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        run_get(&cfg, &nzb, &out, &borrowed)
    })
    .await
    .unwrap();
    (log, ok, t0.elapsed())
}

/// Print a run's whole log when `NZBFAST_FAULT_TRACE` is set.
///
/// These shapes assert on outcomes rather than on wording, which is
/// right (§282's lanes are rewording the log as this lands) and leaves
/// nothing to read when one surprises you. This is how you read it,
/// without editing the test to get it.
fn trace(tag: &str, log: &str) {
    if std::env::var_os("NZBFAST_FAULT_TRACE").is_some() {
        eprintln!("--- {tag} ---\n{log}\n--- end {tag} ---");
    }
}

/// A payload whose every PAR2 block is unique.
///
/// `super::payload` is a byte pattern of period 65536 in its index plus
/// a 512-byte-granular ramp that itself wraps at 256, so over 64 KiB
/// blocks it repeats every SECOND block - and the repair engine's
/// adoption scan then legitimately recovers a "missing" block from a
/// duplicate elsewhere in the same file. That is the engine being
/// clever, but it silently converts a shape about recovery data into a
/// shape about self-similarity, which is not what any of these tests
/// mean. splitmix64 keeps every block distinct and stays deterministic.
fn unique_payload(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed;
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        out.extend_from_slice(&(z ^ (z >> 31)).to_le_bytes());
    }
    out.truncate(n);
    out
}

/// How many times the run escalated its recovery fetch.
///
/// Matched on the `[repair]` planner's own wording, which
/// `crates/nzbfast/src/repair.rs` owns; §282's escalation lane is
/// actively reworking that file, so if this stops counting, the count
/// is what matters and the string is what moved. Both spellings the
/// planner emits are counted (`fetching` and the reuse arm).
fn recovery_fetch_rounds(log: &str) -> usize {
    log.lines()
        .filter(|l| l.contains("[repair]") && (l.contains("fetching") || l.contains("reusing")))
        .count()
}

/// Did the run leave an importable payload file behind?
///
/// The outcome that matters more than any exit status: a job that could
/// not repair must not put a holey file where an *arr will import it.
/// The quarantine renames it to `*.nzbfast-partial`.
fn importable(fx: &Fixture, name: &str) -> bool {
    fx.dir.join("out").join(name).exists()
}

/// **Shape 1 - the recovery set is dead and the payload is healthy.**
///
/// This is §282's incident, reduced. Live, on 24 Aug 2026: a 14.87 GB
/// post arrived 99.2% complete and the job then spent 46 minutes asking
/// one provider for recovery volumes it had already demonstrated it
/// would not serve - `fetched 68.9 MB of recovery data in 229.09s (1206
/// article failures)` against a 1024 MB request, followed by two further
/// escalations on no new evidence. The payload would have repaired
/// comfortably; what was dead was the recovery.
///
/// Asserted here: the job reaches an honest terminal verdict, it does
/// not claim success, it does not hang, and **the verdict names the
/// recovery set as the casualty rather than the payload** - which is
/// §283 item 13, closed here.
///
/// That last assertion needed two things that did not exist when this
/// shape was written. §282 item 17 built the rung
/// (`diag::recovery_is_the_casualty`) and left its seam
/// (`LossCauses::recovery_unobtainable`) with no producer, because
/// `get::plan` never puts a named `Par2Volume` in the main plan and
/// every DOWNLOAD-time recovery counter is therefore unreachable by
/// construction on a conventionally named set. §282 item 4 built the
/// producer: the volumes are fetched later, in the repair ladder, and
/// its yield gate is what measures that the source will not serve them.
///
/// And it needed one thing of this fixture's, which is the part worth
/// reading before changing the geometry: the recovery set is posted at
/// [`RECOVERY_YIELD_ART`] rather than at one article per block, because
/// item 4's gate refuses to judge a sample under sixteen articles and a
/// 64 KiB-per-block set is about five. At the old geometry this shape
/// killed 93% of the recovery set and the product correctly declined to
/// call the source dead, so the clause could not fire however the seam
/// was wired. Kill the payload harder instead and it still cannot fire,
/// for the opposite reason - the rung refuses to blame the parity on a
/// job that lost more than a twentieth of its payload, which is
/// `diag::PAYLOAD_INTACT_DEN` and is exactly the precision this clause
/// is worth having for.
///
/// NOT asserted: the escalation count. That is §282 item 4's own
/// property and `e2e_repair::an_unservable_recovery_set_declines_as_
/// short_not_malformed` pins it; here it is measured and printed, so a
/// regression in it shows up in the output of a shape that is about
/// something else.
#[tokio::test(flavor = "multi_thread")]
async fn dead_recovery_set_over_a_healthy_payload_fails_honestly() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("fault-deadrec");
    matrix_post_art(&mut fx, 40, 65_536, 8, None, RECOVERY_YIELD_ART);
    let p = plan(&fx);
    let mut chaos = Chaos::default();
    // The live rates: 0.8% of the payload gone, 93% of the recovery.
    p.role(Role::Payload)
        .fraction(0.008)
        .expect_nonempty(&p)
        .missing(&mut chaos);
    // The VOLUMES, not the whole set: live, the main index arrived and
    // the set went live (`[par2] set live: 129 file(s), block size
    // 5505024`) - it was the volumes that would not serve. Killing the
    // index instead is a different shape, and it is shape 8 below.
    p.role(Role::Par2Volumes)
        .fraction(0.93)
        .expect_nonempty(&p)
        .missing(&mut chaos);

    let (log, ok, wall) = run_shape(&fx, chaos, 1).await;
    trace("shape 1", &log);
    assert!(
        !ok,
        "a job that cannot repair must exit nonzero:\n{log}\n{}",
        p.describe_post()
    );
    assert!(
        !log.contains("clean download"),
        "a dead recovery set must not read as a clean download:\n{log}"
    );
    // §283 item 13. The headline, not the counts - the counts are fine
    // and were never the complaint. Asserted on the OPENING rather than
    // on the sentence that follows it, deliberately: the opening is
    // load-bearing beyond the prose, because `diag::fail_kind` keys on
    // it and any other opening leaves `MissingArticles`, which is the
    // one kind the age gate applies to. The evidence clause after it is
    // wording and this module does not pin wording.
    assert!(
        log.contains("the recovery data is what failed, not the payload"),
        "the payload arrived 97.5% intact and the parity is what would \
         not serve - a message that reports this as missing segments \
         sends the user to look at articles, which is where §282's 46 \
         minutes went:\n{log}"
    );
    // Terminal, not wedged. Generous because the box is shared; the
    // point is that it ENDS.
    assert!(
        wall < Duration::from_secs(180),
        "the job took {wall:?} to reach a verdict - §282's 46 minutes \
         were made of exactly this:\n{log}"
    );
    eprintln!(
        "shape 1: {} recovery fetch round(s), wall {wall:?}",
        recovery_fetch_rounds(&log)
    );
}

/// **Shape 2 - the recovery volume arrives in PART.**
///
/// §282 item 15, live: `fetched 68.9 MB of recovery data in 229.09s
/// (1206 article failures)` and then `mapped repair declined (recovery
/// set malformed: 0 recovery slice(s) for 163 missing block(s))`. Real
/// bytes of real volumes were on disk and the mapped path reported no
/// usable slices at all.
///
/// The geometry here makes the question sharp: ONE volume holding all 8
/// recovery blocks, with its TAIL articles refused. The head of the
/// volume - its packets and its first slices - arrives whole, and one
/// payload block is damaged, so a single surviving slice is enough. If
/// a partial volume contributes nothing, this job fails with recovery
/// data sitting on disk, which is exactly item 15.
#[tokio::test(flavor = "multi_thread")]
async fn a_partially_fetched_recovery_volume_still_repairs() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("fault-partvol");
    let data = matrix_post_vols(&mut fx, 40, 65_536, 8, Some(1));
    let p = plan(&fx);
    let mut chaos = Chaos::default();
    p.role(Role::Payload)
        .evenly(1)
        .expect_nonempty(&p)
        .missing(&mut chaos);
    // The volume's TAIL: the last half of its articles. Its head - the
    // Main/FileDesc/IFSC packets every volume duplicates, and the first
    // recovery slices behind them - arrives whole.
    let vol = p.role(Role::Par2Volume(0)).expect_nonempty(&p);
    let tail: Vec<String> = vol.ids()[vol.len() / 2..].to_vec();
    chaos.missing.extend(tail);

    let (log, ok, wall) = run_shape(&fx, chaos, 1).await;
    trace("shape 2", &log);
    assert!(
        ok,
        "one damaged block against a volume whose head arrived whole \
         must repair - §282 item 15 is this failing:\n{log}"
    );
    // The contrast that makes this shape about PARTIAL arrival rather
    // than about repair in general is
    // `a_second_backbone_fills_the_hole_that_kills_a_single_provider`,
    // whose fleet-1 arm is this fixture with the WHOLE volume refused
    // and correctly fails.
    assert_eq!(
        std::fs::read(fx.dir.join("out/payload.bin")).unwrap(),
        data,
        "the repaired bytes must be the posted bytes"
    );
    eprintln!("shape 2: repaired from a partial volume in {wall:?}");
}

/// **Shape 3 - the payload is dead and the recovery is healthy**, the
/// mirror of shape 1.
///
/// Run as a PAIR on purpose. Both jobs fail, and §282 item 17's cause
/// clause has to tell them apart: shape 1 is "your provider will not
/// serve this post's recovery data", shape 3 is "this post is short and
/// there is not enough parity to rebuild it".
///
/// **The discriminator is the cause clause** (§283 item 13). Until the
/// seam behind it had a producer, the only thing that told these two
/// apart in the product's own output was that shape 3 reaches the
/// shortfall arithmetic and shape 1 does not - a true difference, but
/// an incidental one, and one the user has to know how to read. The
/// arithmetic assertions are kept BELOW the clause rather than deleted
/// with it, because each is still a correctness property in its own
/// right: a post short of parity must reach the arithmetic, and a post
/// that has parity it cannot obtain must never be told it is
/// unrepairable, which is the wrong remedy.
///
/// This is also the pair that catches the tempting bad fix. The clause
/// only earns its keep if it is PRECISE, and the way to make it fire on
/// shape 1 by accident is to loosen `diag::recovery_is_the_casualty`
/// until it fires on shape 3 as well - blaming the parity on a job
/// whose payload died, which is worse than the silence it replaces.
/// Half of that guard is `diag::PAYLOAD_INTACT_DEN` (shape 3 loses half
/// its payload, twenty times the admitted share) and half is the
/// producer being the yield gate rather than any failure: shape 3's
/// recovery set is fetched, arrives whole, and is simply not enough,
/// which is `RepairShortfall::Blocks` and not `Unservable`.
#[tokio::test(flavor = "multi_thread")]
async fn a_dead_payload_and_a_dead_recovery_set_are_distinguishable() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    // Shape 3: 20 of 40 blocks gone against 8 recovery blocks. The
    // arithmetic cannot close and the post is what is wrong.
    let mut fx = Fixture::new("fault-deadpay");
    matrix_post(&mut fx, 40, 65_536, 8);
    let p = plan(&fx);
    let mut chaos = Chaos::default();
    p.role(Role::Payload)
        .fraction(0.5)
        .expect_nonempty(&p)
        .missing(&mut chaos);
    let (dead_payload, ok, _) = run_shape(&fx, chaos, 1).await;
    trace("shape 3", &dead_payload);
    assert!(!ok, "20 of 40 blocks gone cannot repair:\n{dead_payload}");
    assert!(
        !importable(&fx, "payload.bin"),
        "a holey file must never be left importable:\n{dead_payload}"
    );
    assert!(
        !dead_payload.contains("the recovery data is what failed, not the payload"),
        "half this payload is gone and no amount of parity would have \
         saved it - blaming the recovery set here is the bad fix this \
         pair exists to catch:\n{dead_payload}"
    );
    assert!(
        dead_payload.contains("unrepairable"),
        "a post short of parity must reach the shortfall arithmetic:\n{dead_payload}"
    );

    // Shape 1 again, for the contrast: parity enough for the damage,
    // and a provider that will not serve it.
    let mut fx2 = Fixture::new("fault-deadrec2");
    // Same geometry as shape 1, and for the reason written up there:
    // the yield gate that produces this arm's verdict will not judge a
    // sample under sixteen articles.
    matrix_post_art(&mut fx2, 40, 65_536, 8, None, RECOVERY_YIELD_ART);
    let p2 = plan(&fx2);
    let mut chaos2 = Chaos::default();
    p2.role(Role::Payload)
        .evenly(1)
        .expect_nonempty(&p2)
        .missing(&mut chaos2);
    p2.role(Role::Par2Volumes)
        .expect_nonempty(&p2)
        .missing(&mut chaos2);
    let (dead_recovery, ok2, _) = run_shape(&fx2, chaos2, 1).await;
    trace("shape 1 (paired)", &dead_recovery);
    assert!(
        !ok2,
        "no recovery obtainable, so no repair:\n{dead_recovery}"
    );
    assert!(
        dead_recovery.contains("the recovery data is what failed, not the payload"),
        "the two failures have to be distinguishable in the sentence \
         the user actually reads, and this is the half that was silent \
         until §283 item 13:\n{dead_recovery}"
    );
    assert!(
        !dead_recovery.contains("unrepairable"),
        "the NZB carries 8 blocks for 1 damaged one - this job is not \
         short of parity, it is short of a provider that will serve \
         it, and saying otherwise sends the user to the wrong \
         remedy:\n{dead_recovery}"
    );
}

/// **Shape 4 - damage just under, exactly at, and just over the recovery
/// block count.**
///
/// The boundary is where an "unrepairable" verdict is either correct or
/// a bug, and nothing else in the suite states it as arithmetic: the
/// fixture's article size IS its PAR2 block size, so k damaged articles
/// are k damaged blocks against a recovery count `par2 create -c` pinned
/// exactly.
///
/// Under and AT must repair to the posted bytes. Over must fail, and
/// must not leave the holey file importable.
#[tokio::test(flavor = "multi_thread")]
async fn the_recovery_block_boundary_is_exact_in_both_directions() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    const RECOVERY: usize = 8;
    for (damage, must_repair) in [
        (RECOVERY - 1, true),
        (RECOVERY, true),
        (RECOVERY + 1, false),
    ] {
        let mut fx = Fixture::new(&format!("fault-edge{damage}"));
        let data = matrix_post(&mut fx, 40, 65_536, RECOVERY);
        let p = plan(&fx);
        let mut chaos = Chaos::default();
        let sel = p.role(Role::Payload).evenly(damage).expect_nonempty(&p);
        assert_eq!(sel.len(), damage, "the shape must damage what it says");
        sel.missing(&mut chaos);

        let (log, ok, _) = run_shape(&fx, chaos, 1).await;
        trace(&format!("shape 4 ({damage} damaged)"), &log);
        assert_eq!(
            ok, must_repair,
            "{damage} damaged block(s) against {RECOVERY} recovery block(s):\n{log}"
        );
        if must_repair {
            assert_eq!(
                std::fs::read(fx.dir.join("out/payload.bin")).unwrap(),
                data,
                "{damage} damaged: repaired bytes differ from the posted bytes"
            );
        } else {
            assert!(
                !importable(&fx, "payload.bin"),
                "{damage} damaged: a holey file must not be left importable:\n{log}"
            );
            assert!(
                log.contains("unrepairable"),
                "{damage} damaged: one block past the parity must say so:\n{log}"
            );
        }
    }
}

/// Run `nzbfast check` - the pre-flight STAT sweep - and return
/// (stdout+stderr, success).
fn run_check(config: &std::path::Path, nzb: &std::path::Path) -> (String, bool) {
    let out = Command::new(env!("CARGO_BIN_EXE_nzbfast"))
        .env("NZBFAST_OPEN", "1")
        .arg("--config")
        .arg(config)
        .arg("check")
        .arg(nzb)
        .output()
        .expect("run nzbfast check");
    (
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
        out.status.success(),
    )
}

/// **Shape 5 - a fresh post still propagating.**
///
/// Every article 430s and the post is one day old, which is inside
/// `diag::GONE_MIN_AGE_DAYS` (3). Propagation across the backbones is
/// normally minutes and occasionally hours, so "430 everywhere" on a
/// post this fresh is NOT evidence the post is dead - and the memory
/// `nzbfast-retry-propagation-trap` is the live run where that
/// distinction was got wrong in the other direction.
///
/// Asserted as a PAIR against the same post backdated past the gate,
/// because the claim is about the difference: the old post may be
/// called gone, the fresh one may not. Once §282's alternate hunt
/// lands, the fresh arm is also where "the hunt must NOT fire" gets
/// pinned - every alternate a hunt found for a post this fresh would be
/// the same fresh post (§282 item 10).
#[tokio::test(flavor = "multi_thread")]
async fn a_fresh_post_that_430s_everywhere_is_not_called_dead() {
    let build = |age_days: i64, tag: &str| {
        let mut fx = Fixture::new(tag);
        let data = unique_payload(400_000, 0x0283_0005);
        fx.add_file("fresh.bin", &data, 40_000);
        fx.date = super::unix_now() - age_days * 86_400;
        fx
    };
    let mut logs = Vec::new();
    for (age, tag) in [(1i64, "fault-fresh"), (30, "fault-old")] {
        let fx = build(age, tag);
        let p = plan(&fx);
        let mut chaos = Chaos::default();
        p.role(Role::Everything)
            .expect_nonempty(&p)
            .missing(&mut chaos);
        let (log, ok, _) = run_shape(&fx, chaos, 1).await;
        trace(&format!("shape 5 ({age}d)"), &log);
        assert!(!ok, "a wholly dead post must fail:\n{log}");
        logs.push(log);
    }
    let (fresh, old) = (&logs[0], &logs[1]);
    // `diag::incomplete_reason`'s own opening, which `fail_kind` maps
    // to `FailKind::Gone` - the classification that reports the release
    // to an indexer and does NOT arm the automatic retry. The wording
    // belongs to diag.rs, which §282 is not touching.
    let gone_clause = "post is gone";
    assert!(
        old.contains(gone_clause),
        "a 30-day-old post that 430s everywhere is gone, and the \
         message must say so:\n{old}"
    );
    assert!(
        !fresh.contains(gone_clause),
        "a ONE-day-old post that 430s everywhere is very likely still \
         propagating - calling it gone suppresses the retry that would \
         have healed it:\n{fresh}"
    );
}

/// **Shape 6 - takedown by replacement.**
///
/// STAT answers 223 for every article and every body then fails its
/// yEnc CRC. This is the FALSE GREEN written into
/// `crates/nzbkit/src/preflight.rs`'s module header - "a clean sweep is
/// not a clean post" - and as far as TODO 283 could tell, nothing
/// exercised it end to end. It is asserted from BOTH sides here,
/// because half of it is the interesting half: `check` reports the post
/// fully available (which is the documented, unavoidable false green),
/// and `get` then refuses to call the result complete (which is the
/// backstop that makes the false green survivable).
#[tokio::test(flavor = "multi_thread")]
async fn a_replaced_post_sweeps_clean_and_still_cannot_complete() {
    let mut fx = Fixture::new("fault-replaced");
    let data = unique_payload(400_000, 0x0283_0006);
    fx.add_file("taken.bin", &data, 40_000);
    let p = plan(&fx);
    let mut chaos = Chaos::default();
    p.role(Role::Everything)
        .expect_nonempty(&p)
        .corrupt(&mut chaos);
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();

    let (check_log, check_ok) = {
        let (c, n) = (cfg.clone(), nzb.clone());
        tokio::task::spawn_blocking(move || run_check(&c, &n))
            .await
            .unwrap()
    };
    trace("shape 6 check", &check_log);
    assert!(
        check_ok && check_log.contains("verdict: COMPLETE"),
        "STAT answers 223 for every article, so the sweep is green - \
         this is the documented false green, not a bug, and pinning it \
         is how the day it silently stops being possible gets \
         noticed:\n{check_log}"
    );

    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    trace("shape 6 get", &log);
    assert!(
        !ok,
        "every body failed its CRC - the download cannot be complete:\n{log}"
    );
    assert!(
        !importable(&fx, "taken.bin"),
        "a post replaced by dummies must not leave an importable \
         file - the sweep already said green, so this is the only \
         thing standing between the user and a corrupt import:\n{log}"
    );
    let landed = fx.dir.join("out/taken.bin.nzbfast-partial");
    if landed.exists() {
        assert_ne!(
            std::fs::read(&landed).unwrap(),
            data,
            "the fixture must actually be serving replaced bytes"
        );
    }
}

/// **Shape 7 - stalled AND holding real 430s at once.**
///
/// The memory `nzbfast-retry-propagation-trap` records a live run that
/// was both, and a message that reassured the user about a release four
/// providers had just called short 2031 times. `diag::LossCauses` has
/// an explicit precedence for it - the stall clause opens, because a
/// stall is OUR failure and has to say so first, and the 430s must
/// still be reported rather than papered over with "not evidence that
/// anything is missing".
///
/// Both conditions are induced at once: a brownout takes the frontend
/// mute mid-run (the stall), while a fifth of the post is genuinely
/// refused (the 430s).
#[tokio::test(flavor = "multi_thread")]
async fn a_run_that_both_stalled_and_collected_430s_reports_both() {
    let mut fx = Fixture::new("fault-both");
    let data = unique_payload(2_000_000, 0x0283_0007);
    fx.add_file("both.bin", &data, 40_000);
    let p = plan(&fx);
    let mut chaos = Chaos {
        // The frontend goes mute after a handful of bodies and never
        // comes back - the pool stalls with articles still outstanding.
        brownout_after: 6,
        ..Default::default()
    };
    p.role(Role::Payload)
        .fraction(0.2)
        .expect_nonempty(&p)
        .missing(&mut chaos);

    // The deadlock watchdog's window is 180 s in production; the
    // override exists so a stall-shaped test does not have to wait it
    // out, and without it this shape runs for three minutes.
    let (log, ok, _) = run_shape_env(&fx, chaos, 1, &[("NZBFAST_STALL_ABORT_SECS", "8")]).await;
    trace("shape 7", &log);
    assert!(!ok, "a stalled run must not report success:\n{log}");
    assert!(
        log.contains("stalled"),
        "a stall is our failure and has to say so first:\n{log}"
    );
    assert!(
        !log.contains("not evidence that anything is missing"),
        "servers refused a fifth of this post - a message that tells \
         the user nothing is missing is the propagation trap:\n{log}"
    );
}

/// (eager MB, total MB) from the launch banner - the observable that
/// says whether the recovery volumes were DEFERRED or fetched with the
/// payload. `announce_plan` in `get/mod.rs` writes it.
fn eager_and_total(log: &str) -> Option<(f64, f64)> {
    let line = log.lines().find(|l| l.contains(" MB eager of "))?;
    let (a, rest) = line.split_once(" MB eager of ")?;
    let eager: f64 = a.rsplit('(').next()?.trim().parse().ok()?;
    let total: f64 = rest.split(" MB total").next()?.trim().parse().ok()?;
    Some((eager, total))
}

/// Rename every posted `.par2` file through `f`, in place.
///
/// The NZB subject and the yEnc-declared name both move, which is what
/// a poster who names volumes their own way actually produces.
fn rename_par2_posts(fx: &mut Fixture, f: impl Fn(usize) -> String) {
    let mut n = 0usize;
    for (name, _) in fx.nzb_files.iter_mut() {
        if name.to_ascii_lowercase().ends_with(".par2") {
            *name = f(n);
            n += 1;
        }
    }
}

/// **Shape 8 - a recovery set named `.vol-NN.par2`.**
///
/// The memory `nzbfast-par2-vol-dash-naming-gap` is the live version:
/// the bare-ordinal convention (playWEB/NORViNE/GRACE posts) was not
/// recognised as a recovery-volume suffix, so a `.vol-NN` set was
/// classified as PAYLOAD - fetched eagerly, 7.5 GB of it measured on
/// one 42 GiB post, and carried onto the release stem where it
/// shattered the release in the index.
///
/// Two halves, and both matter: the volumes must be DEFERRED (the
/// bytes), and they must still be REACHABLE when a block needs
/// rebuilding (the repair). A fix that classified them and then could
/// not use them would pass half of this.
#[tokio::test(flavor = "multi_thread")]
async fn a_bare_ordinal_recovery_set_defers_and_still_repairs() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("fault-voldash");
    let data = matrix_post(&mut fx, 40, 65_536, 8);
    // par2cmdline writes `testset.vol0+1.par2`; the poster this shape
    // models writes `release.vol-01.par2`. The main index keeps a plain
    // name, as it does live.
    rename_par2_posts(&mut fx, |i| {
        if i == 0 {
            "release.par2".to_string()
        } else {
            format!("release.vol-{i:02}.par2")
        }
    });
    let p = plan(&fx);
    assert_eq!(
        p.role(Role::Par2Volumes).files(),
        p.files().len() - 2,
        "every renamed volume must still classify as recovery - if this \
         fails, the naming gap is back:\n{}",
        p.describe_post()
    );
    let mut chaos = Chaos::default();
    p.role(Role::Payload)
        .evenly(1)
        .expect_nonempty(&p)
        .missing(&mut chaos);

    let (log, ok, _) = run_shape(&fx, chaos, 1).await;
    trace("shape 8", &log);
    let (eager, total) = eager_and_total(&log).unwrap_or_else(|| panic!("no plan banner:\n{log}"));
    assert!(
        eager < total,
        "a `.vol-NN` recovery set must be DEFERRED, not pulled with the \
         payload: {eager} MB eager of {total} MB total:\n{log}"
    );
    assert!(ok, "the deferred set must still repair the damage:\n{log}");
    assert_eq!(
        std::fs::read(fx.dir.join("out/payload.bin")).unwrap(),
        data,
        "repaired bytes differ from the posted bytes"
    );
}

/// **Shape 9 - recovery volumes under junk names.**
///
/// Nothing reaching the client says `.par2`: not the NZB subject, not
/// the yEnc-declared filename. Native repair finds the set anyway by
/// sniffing PAR2 packet magic out of the bodies; par2cmdline cannot,
/// because it is pointed at a recovery set BY NAME and there is no name
/// to point it at. TODO 283 records that as a claimed advantage with no
/// test asserting it, and this is that test.
///
/// The second assertion is the one that makes it about the advantage
/// rather than about repair in general: par2cmdline, handed this
/// directory, has nothing it can be given as a recovery set.
#[tokio::test(flavor = "multi_thread")]
async fn junk_named_recovery_volumes_are_found_by_packet_magic() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("fault-junkpar2");
    let data = unique_payload(40 * 65_536, 0x0283_0009);
    fx.add_file("payload.bin", &data, 65_536);
    assert!(
        fx.add_par2_obfuscated(20, &["payload.bin"], 65_536),
        "par2 create failed"
    );
    let p = plan(&fx);
    assert_eq!(
        p.role(Role::Par2Volumes).len() + p.role(Role::Par2Main).len(),
        0,
        "the point of this shape is that NOTHING classifies by name:\n{}",
        p.describe_post()
    );
    // par2cmdline's whole interface is a `.par2` file to be pointed at.
    assert!(
        !fx.nzb_files
            .iter()
            .any(|(n, _)| n.to_ascii_lowercase().contains(".par2")),
        "no posted name may carry .par2, or the advantage is not \
         being tested:\n{}",
        p.describe_post()
    );
    let mut chaos = Chaos::default();
    // Damage inside the PAYLOAD only - the recovery set is nameless but
    // healthy, which is the shape a remux poster actually produces.
    p.role(Role::Named("payload.bin".into()))
        .evenly(1)
        .expect_nonempty(&p)
        .missing(&mut chaos);

    let (log, ok, _) = run_shape(&fx, chaos, 1).await;
    trace("shape 9", &log);
    assert!(
        ok,
        "a nameless recovery set must still repair - this is the \
         packet-magic sniff:\n{log}"
    );
    assert_eq!(
        std::fs::read(fx.dir.join("out/payload.bin")).unwrap(),
        data,
        "repaired bytes differ from the posted bytes"
    );
    assert!(
        log.contains("bootstrapping the PAR2 set from it"),
        "the set must have been elected by sniffing, not by name:\n{log}"
    );
}

/// **Shape 10 - the same fault at fleet size 1 and at 5.**
///
/// A single-provider evening on 24 Aug 2026 turned up four defects in
/// one sitting, and this is why: a second backbone silently fills holes
/// that are defects, so some faults are only faults at fleet size 1,
/// and running one fleet size is running half the matrix.
///
/// The pair here is shape 1's fault - a recovery set the provider will
/// not serve - run against one provider and then against five, four of
/// which hold the post. The difference is the finding: at 1 the job
/// dies, at 5 it repairs and the user never learns that a provider
/// refused a whole recovery set. Both verdicts are correct; what the
/// pair pins is that the second one is REACHED, so a routing change
/// that stopped consulting the healthy peers would show up here rather
/// than in somebody's evening.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_backbone_fills_the_hole_that_kills_a_single_provider() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("fault-fleet");
    let data = matrix_post(&mut fx, 40, 65_536, 8);
    let p = plan(&fx);
    let mut chaos = Chaos::default();
    p.role(Role::Payload)
        .evenly(1)
        .expect_nonempty(&p)
        .missing(&mut chaos);
    p.role(Role::Par2Volumes)
        .expect_nonempty(&p)
        .missing(&mut chaos);

    let (alone, ok_alone, _) = run_shape(&fx, chaos.clone(), 1).await;
    trace("shape 10 (fleet 1)", &alone);
    assert!(
        !ok_alone,
        "one provider, no recovery obtainable: the job cannot \
         repair:\n{alone}"
    );

    let fx2 = {
        let mut fx2 = Fixture::new("fault-fleet5");
        let d = matrix_post(&mut fx2, 40, 65_536, 8);
        assert_eq!(d, data, "both legs must be the same post");
        fx2
    };
    let (fleet, ok_fleet, _) = run_shape_mixed(&fx2, chaos, 4).await;
    trace("shape 10 (fleet 5)", &fleet);
    assert!(
        ok_fleet,
        "four healthy providers hold the recovery set the fifth \
         refuses - the job must complete:\n{fleet}"
    );
    assert_eq!(
        std::fs::read(fx2.dir.join("out/payload.bin")).unwrap(),
        data,
        "repaired bytes differ from the posted bytes"
    );
}

/// **Shape 11 - a refusal that costs a real round trip.**
///
/// Several §282 defects are only visible when a 430 is not free: the 46
/// minutes were made of them. `Chaos::missing_delay_ms` exists for
/// exactly this and is zero everywhere else in the suite, which keeps
/// every other test at localhost speed and makes every other test blind
/// to the cost of driving a dead queue to terminal.
///
/// The figures are a measured cold-provider tier (~10-13 Mbps per
/// connection, one backbone's unwarmed spool): a 64 KiB article at
/// 12 Mbps is ~44 ms of body time, and a refusal is a full
/// transatlantic round trip at
/// ~50 ms. What is asserted is that the run still REACHES a terminal
/// verdict and does not spend the wall on nothing - the payload's
/// refusals dominate, so the bound is stated against the article count
/// rather than as a magic number.
#[tokio::test(flavor = "multi_thread")]
async fn a_dead_queue_at_cold_provider_latency_still_terminates() {
    let mut fx = Fixture::new("fault-cold");
    let arts = 60usize;
    let data = unique_payload(arts * 40_000, 0x0283_0011);
    fx.add_file("cold.bin", &data, 40_000);
    fx.date = super::unix_now() - 30 * 86_400;
    let p = plan(&fx);
    let mut chaos = Chaos {
        delay_ms: 44,
        missing_delay_ms: 50,
        // Real providers split both ways on echoing the id, and the
        // un-echoed form costs a SECOND ask for every article the
        // provider does not have (see `Chaos::echo_missing_id`). The
        // expensive half is the one worth timing.
        echo_missing_id: false,
        ..Default::default()
    };
    p.role(Role::Everything)
        .expect_nonempty(&p)
        .missing(&mut chaos);

    let (log, ok, wall) = run_shape(&fx, chaos, 1).await;
    trace("shape 11", &log);
    assert!(!ok, "a wholly dead post must fail:\n{log}");
    // The refusals were really paid for: at 50 ms each over 4
    // connections, 60 articles asked up to twice cannot resolve
    // instantly. A rig that silently stopped delaying would make every
    // bound below meaningless.
    assert!(
        wall > Duration::from_millis(300),
        "the fixture did not actually charge for its refusals ({wall:?}) \
         - this shape is worthless at localhost speed:\n{log}"
    );
    // And it still terminates well inside the deadlock watchdog's
    // 180 s window, which is the property §282's 46 minutes did not
    // have. Generous: this box is shared.
    assert!(
        wall < Duration::from_secs(60),
        "driving {arts} refused article(s) to terminal took {wall:?}:\n{log}"
    );
}

/// **Shape 12 - split brain: the right id, the wrong article.**
///
/// A storage backend answers with a fully valid, self-consistent yEnc
/// body that is simply not the article that was asked for. Its own
/// pcrc32 PASSES, so nothing about the bytes gives it away; only the
/// article's declared identity can. `Chaos::swap` was built for this -
/// "seen live as downloads complete but never verify" - and TODO 283's
/// twelfth shape is that **nothing in the test tree used the knob**: a
/// census on 24 Aug 2026 found zero references to `swap` in
/// `crates/nzbfast/tests`, so the one fault whose whole signature is
/// "everything looks fine" had no end-to-end coverage at all.
///
/// ACROSS FILES, and that is not a detail. A yEnc body declares its own
/// name, part number and begin offset, so two articles of the SAME file
/// swapped with each other still land where they belong - measured, and
/// the reason this shape is written the way it is. Handing file A's
/// bytes to a slot expecting file B's is the shape a mismatched backend
/// actually produces.
///
/// **What it found, 24 Aug 2026: nothing to fix.** Both files come out
/// BYTE-CORRECT with every article served under the wrong id, because
/// the pipeline places a body by the identity the body declares rather
/// than by the id that was asked for. That is the right design and it
/// makes this whole fault class inert - so this test asserts the
/// correctness POSITIVELY. If a future routing change ever files a body
/// by the requested id instead, this goes red, which is the only reason
/// the property is worth a test at all.
#[tokio::test(flavor = "multi_thread")]
async fn a_backend_serving_the_wrong_article_cannot_pass_as_complete() {
    let mut fx = Fixture::new("fault-splitbrain");
    let a = unique_payload(400_000, 0x0283_0012);
    let b = unique_payload(400_000, 0x0283_00b2);
    fx.add_file("alpha.bin", &a, 40_000);
    fx.add_file("beta.bin", &b, 40_000);
    let p = plan(&fx);
    let mut chaos = Chaos::default();
    let alpha = p.role(Role::Named("alpha.bin".into())).expect_nonempty(&p);
    let beta = p.role(Role::Named("beta.bin".into())).expect_nonempty(&p);
    alpha.swap_with(&beta, &mut chaos);

    let (log, ok, _) = run_shape(&fx, chaos, 1).await;
    trace("shape 12", &log);
    assert!(
        ok,
        "every body is a valid article of this post, merely fetched \
         under the other file's id - the download can and must \
         complete:\n{log}"
    );
    let landed = |n: &str| std::fs::read(fx.dir.join("out").join(n)).unwrap_or_default();
    assert_eq!(
        landed("alpha.bin"),
        a,
        "a body must be filed by the identity IT declares, not by the \
         id that was asked for - otherwise this file is scrambled and \
         the job called it complete:\n{log}"
    );
    assert_eq!(landed("beta.bin"), b, "the other half of the swap:\n{log}");
}
