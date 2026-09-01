//! W4-12 and X5-11: the late-set pass is a BOUNDED FIXPOINT, and these
//! are the two shapes that made it one.
//!
//! Until 31 Aug 2026 `get::latesets::apply_nonactivated_disk_sets` took
//! a single `disk_sets_scoped(out_dir, Nested)` census, looped over it
//! once, and never looked again: nothing in that body re-censused the
//! directory, and nothing re-ran a set that failed earlier in the same
//! loop.
//!
//! That is fine for the chain F12 was written for, where BOTH levels'
//! packet files reach disk off the wire and both are in the one census.
//! It was not fine for the two shapes here, which are the same seam from
//! two sides:
//!
//! * **W4-12** - the inner set's packet files are not on disk at census
//!   time at all. The outer set's own repair CREATES them, which is
//!   precisely what an outer set is FOR. The census was already taken,
//!   so the set that names the payload was never consulted and the
//!   payload kept its hash name. **Measured red on the baseline:
//!   `movie.bin` delivered at 0 bytes.**
//! * **X5-11** - the inner set's id IS in the census (a recovery volume
//!   landed) but its Main packet did not, so it is skipped with an
//!   error. The outer set then materialises that Main. Nothing retried
//!   the known-failed id, so the same payload is lost by a different
//!   route. X5-11 is the STRICTER row: a fixpoint that only revisits
//!   NEWLY DISCOVERED ids fixes W4-12 and still fails this. It did not
//!   reproduce (see the second arm below) and is landed as a pass pin.
//!
//! Both are pins on shipped behaviour now. The loop re-censuses after
//! any set REPAIRS, retries ids that failed, stops on no progress, and
//! caps the rounds at `MAX_LATE_SET_ROUNDS` so a reconstruct cycle
//! cannot spin. X5-13 is the third question on the same loop (it has no
//! cancellation token) and needs a process-control harness rather than a
//! fixture; it is recorded in the round report rather than probed here.
//!
//! ONE CORRECTION TO CARRY, because the sibling `donorshare` module's
//! note made the same mistake and both are worth reading together: set
//! visit order is NOT the raw `read_dir` order the capability round
//! reported. `disk_sets_scoped` builds a `PacketCatalog`, and
//! `PacketCatalog::relist` sorts its file list by path before anything
//! walks it - so order has always been a deterministic function of the
//! names on disk, which is exactly why the `c_first` parameter below
//! works at all. It was never a coin.
//!
//! Method note, paid for once by the wave5 lane: keep the `Fixture`
//! alive past every assertion. It owns the `ScratchDir` guard, so a
//! helper that returns only the output path is graded against a tree
//! that has already been deleted, which reads as a spectacular false
//! red.
//!
//! A child of [`super`] rather than a sibling of `e2e.rs`: `e2e.rs` sits AT
//! its size-gate baseline with no room for another `mod` line, and this row
//! belongs to that parent's subject anyway.

use super::*;
use crate::payloads;

/// `par2 create` a set named `base` over `files`, then MOVE the produced
/// `.par2` files out of the fixture directory and hand back their paths.
///
/// Moved rather than left in place because the next `par2 create` in the
/// chain must cover exactly these files and nothing else, and because
/// `Fixture::add_*` writes its payload into the same directory.
fn create_par2(
    fx: &Fixture,
    base: &str,
    redundancy: u32,
    block: u64,
    files: &[&str],
) -> Vec<PathBuf> {
    let st = Command::new("par2")
        .arg("create")
        .arg(format!("-r{redundancy}"))
        .arg(format!("-s{block}"))
        .arg("-q")
        .arg(base)
        .args(files)
        .current_dir(&fx.dir)
        .status();
    assert!(
        matches!(st, Ok(s) if s.success()),
        "par2 create failed for {base}"
    );
    // ONLY the files this call produced. A `.par2` filter alone sweeps
    // up the packet files of the level BELOW - which the outer create
    // needs sitting in this directory to cover them - and moving those
    // out from under the caller makes the next line fail on a file that
    // is no longer there. Measured 31 Aug 2026: that fixture bug reads
    // as a clean red on the product row, which is exactly the false
    // negative this suite exists to avoid.
    let mut made: Vec<PathBuf> = std::fs::read_dir(&fx.dir)
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            let named_by_us = p
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with(base));
            (named_by_us && p.extension().is_some_and(|x| x == "par2")).then_some(p)
        })
        .collect();
    made.sort();
    assert!(!made.is_empty(), "par2 create produced nothing for {base}");
    let stash = fx.dir.join(format!("stash-{base}"));
    std::fs::create_dir_all(&stash).unwrap();
    made.into_iter()
        .map(|p| {
            let to = stash.join(p.file_name().unwrap());
            std::fs::rename(&p, &to).unwrap();
            to
        })
        .collect()
}

/// Post one already-built file under a HASH subject AND a HASH yEnc
/// name, so nothing on the wire carries its real name and no set can
/// activate in-stream from it. Returns the bracketed message ids, so a
/// caller can refuse them.
fn post_obfuscated(fx: &mut Fixture, tag: &str, data: &[u8], art_size: usize) -> Vec<String> {
    let hash = format!("{tag}zXm9rTb");
    let segs = make_file_articles(&hash, data, art_size, tag, &mut fx.articles);
    let ids = segs.iter().map(|(id, _, _)| format!("<{id}>")).collect();
    fx.nzb_files.push((hash, segs));
    ids
}

/// One `get` run against an in-process mock server.
async fn run_chain(fx: &Fixture, chaos: Chaos) -> (String, bool, PathBuf) {
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
    if std::env::var("CHAINSET_DUMP_LOG").is_ok() {
        eprintln!("==== run log ====\n{log}\n==== end ====");
    }
    (log, ok, out)
}
/// How much of the INNERMOST set's own packet files reach the wire.
#[derive(Clone, Copy, PartialEq)]
enum InnerOnWire {
    /// W4-12: none of them. That set does not exist anywhere until the
    /// middle set - itself only rebuilt during this same pass - creates
    /// it, so it cannot be in a census taken before the pass began.
    Nothing,
    /// X5-11: C's recovery VOLUMES are covered by set A as well, so A's
    /// pre-settle repair puts them on disk WITHOUT the stream ever
    /// sniffing them - C's id is therefore in the census while its index
    /// packet is not, which is the precondition the row needs. B, applied
    /// later in the same loop, materialises that index.
    ///
    /// Posting C's volumes on the wire instead does NOT reach this seam,
    /// and finding that out cost this probe a draft (measured 31 Aug
    /// 2026): a recovery volume that arrives is identified in-stream
    /// ("bootstrapping the PAR2 set from it"), which makes C an ACTIVE
    /// set, and the late pass skips active ids by construction.
    VolumesOnly,
}

/// The shared chain fixture, and it is THREE levels deep on purpose.
///
/// ```text
///   movie.bin   <- set C (innermost, 100% parity over the payload)
///   C's .par2   <- set B (100% parity over C's packet files)
///   B's .par2   <- set A (100% parity over B's packet files)
/// ```
///
/// A two-level chain does NOT exercise these rows, and finding that out
/// cost this probe its first draft (measured 31 Aug 2026). At two levels
/// the outer set is identified in-stream and repaired during the REPAIR
/// phase, which is strictly before settle - so by the time
/// `apply_nonactivated_disk_sets` takes its census the inner set's
/// packet files are already on disk and the pass finds them. Nothing is
/// missed and the payload lands byte-exact. The one-shot census only
/// bites on a set that comes into existence DURING the pass itself,
/// which needs a third level: A repairs B before settle, the census sees
/// B, the loop applies B and thereby creates C - and the census it is
/// iterating was taken before C existed.
///
/// Only set A reaches the wire intact. Every article of `movie.bin` is
/// refused, and `inner` decides how much of C survives.
///
/// `c_first` decides the ORDER the late-set pass meets the two sets in,
/// and it is a parameter rather than an accident because the first draft
/// of the X5-11 arm passed for free on the benign order (measured 31 Aug
/// 2026). `disk_sets_scoped` orders sets by FIRST SIGHTING over a
/// catalog its own `relist` has SORTED BY PATH, so the order is a
/// deterministic property of the FILENAMES on disk - C's are the hash
/// names it was posted under, B's are the real names A rebuilt it as.
/// Both are chosen here, so both orders are reachable and both are run.
/// A row whose defect appears in only one order is one a single-order
/// probe reports as absent.
async fn run_chain_fixture(
    tag: &str,
    inner: InnerOnWire,
    c_first: bool,
) -> (Fixture, String, bool, PathBuf) {
    let mut fx = Fixture::new(tag);
    let mut chaos = Chaos::default();
    // Sort keys, not decoration: `c_tag` prefixes C's on-disk hash names
    // and `b_base` becomes B's rebuilt real names.
    let (c_tag, b_base) = if c_first {
        ("aac", "zmid")
    } else {
        ("zzc", "amid")
    };

    let movie = payloads::unique_payload(120_000, 91);
    std::fs::write(fx.dir.join("movie.bin"), &movie).unwrap();
    let set_c = create_par2(&fx, "setc", 100, 10_000, &["movie.bin"]);
    std::fs::remove_file(fx.dir.join("movie.bin")).unwrap();

    // Each level's `par2 create` needs the level below it sitting in the
    // fixture directory, and gone again before the next one runs.
    let c_names: Vec<String> = set_c
        .iter()
        .map(|p| {
            let n = p.file_name().unwrap().to_string_lossy().to_string();
            std::fs::copy(p, fx.dir.join(&n)).unwrap();
            n
        })
        .collect();
    let set_b = create_par2(
        &fx,
        b_base,
        100,
        10_000,
        &c_names.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    for n in &c_names {
        std::fs::remove_file(fx.dir.join(n)).unwrap();
    }
    let b_names: Vec<String> = set_b
        .iter()
        .map(|p| {
            let n = p.file_name().unwrap().to_string_lossy().to_string();
            std::fs::copy(p, fx.dir.join(&n)).unwrap();
            n
        })
        .collect();
    // In the X5-11 arm set A covers C's VOLUME files too, so A's
    // pre-settle repair lands them on disk without the stream sniffing
    // them. That is what puts C in the census, broken, before the loop
    // starts - which the wire cannot do, because an arriving recovery
    // volume is identified in-stream and the set becomes ACTIVE.
    let mut a_covers = b_names.clone();
    if inner == InnerOnWire::VolumesOnly {
        for p in &set_c {
            let n = p.file_name().unwrap().to_string_lossy().to_string();
            if n.contains(".vol") {
                std::fs::copy(p, fx.dir.join(&n)).unwrap();
                a_covers.push(n);
            }
        }
    }
    let set_a = create_par2(
        &fx,
        "seta",
        100,
        10_000,
        &a_covers.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    for n in &a_covers {
        std::fs::remove_file(fx.dir.join(n)).unwrap();
    }

    // The payload: an NZB slot under a hash subject and a hash yEnc
    // name, every article refused. Only set C can produce it.
    let ids = post_obfuscated(&mut fx, "movieobf", &movie, 40_000);
    chaos.missing.extend(ids);

    // Set C, refused per `inner`. par2's index file is the one with no
    // `.volNNN+NN.` infix - it carries the Main and FileDesc packets the
    // set cannot start without.
    for (i, p) in set_c.iter().enumerate() {
        let data = std::fs::read(p).unwrap();
        let is_index = !p.file_name().unwrap().to_string_lossy().contains(".vol");
        let ids = post_obfuscated(&mut fx, &format!("{c_tag}{i}"), &data, 40_000);
        // Both arms refuse every one of C's own articles. In the
        // VolumesOnly arm the volumes still reach disk - via A's repair,
        // not the wire - which is the whole point; `is_index` is read
        // only so the shape is legible at the call site.
        let _ = is_index;
        let refuse = true;
        if refuse {
            chaos.missing.extend(ids);
        }
    }

    // Set B, wholly refused in both arms. It exists only once A has
    // rebuilt it, which is what puts it in the census while C is not.
    for (i, p) in set_b.iter().enumerate() {
        let data = std::fs::read(p).unwrap();
        chaos
            .missing
            .extend(post_obfuscated(&mut fx, &format!("mid{i}"), &data, 40_000));
    }

    // Set A, arriving whole.
    for (i, p) in set_a.iter().enumerate() {
        let data = std::fs::read(p).unwrap();
        post_obfuscated(&mut fx, &format!("seta{i}"), &data, 40_000);
    }

    let (log, ok, out) = run_chain(&fx, chaos).await;
    (fx, log, ok, out)
}

/// W4-12: a set that only comes INTO EXISTENCE during this pass must
/// still be applied.
///
/// Set C's packet files are absent from the wire entirely. Set B - which
/// itself only exists because A rebuilt it before settle - is in the
/// census and is applied, and applying it CREATES C, which is precisely
/// what a par2-of-par2 post is for. The census was taken before that
/// happened, so C is never consulted and `movie.bin` never appears.
///
/// Graded on the PAYLOAD and not on a log line: the row is about a file
/// the user does not get, and a fix that turns the loop into a bounded
/// fixpoint will land it whatever the wording.
///
/// **CLOSED 31 Aug 2026** and this is a live pin now, not an ignored
/// row. It reproduced every run on the baseline - `movie.bin` delivered
/// at 0 bytes, measured 2 of 2 attempts - and
/// `apply_nonactivated_disk_sets` is a bounded fixpoint since: it
/// re-censuses after any set REPAIRS, retries ids that failed, stops on
/// no progress and caps the rounds (`MAX_LATE_SET_ROUNDS`). A red here
/// is that fixpoint having been unwound, not a new row.
#[tokio::test(flavor = "multi_thread")]
async fn w4_12_a_set_materialized_by_another_sets_repair_is_still_applied() {
    if !have_par2() {
        eprintln!("w4_12: par2 unavailable - skipping");
        return;
    }
    let (_fx, log, ok, out) = run_chain_fixture("chainw412", InnerOnWire::Nothing, false).await;

    let landed = std::fs::read(out.join("movie.bin")).unwrap_or_default();
    eprintln!("w4_12: rc ok={ok}, movie.bin {} bytes", landed.len());
    assert_eq!(
        landed.len(),
        120_000,
        "applying one late set created the set that names the payload, \
         but the disk census had already been taken, so that set was \
         never consulted\n{log}"
    );
    // ASSERTED since 31 Aug 2026, and it was an `eprintln!` observation
    // before that for one measured reason, now closed. A par2-of-par2
    // post refuses its SIDECAR slots by construction and then rebuilds
    // them from parity, so the verdict counted slots the chain had
    // already reconstructed and MD5-proved;
    // `get::latesets::chain_accounts_for_the_shortfall` is the tier that
    // credits them and it DECLINED here, because `latesets::fits` was a
    // flat 0.9..1.5 ratio of its own and admitted the rebuilt
    // `setc.vol03+4.par2` (42,008 bytes) for the next volume up as well
    // (declared 53,947, a ratio of 1.284). Two of the five sidecar slots
    // were then undecidable in both directions. That band now delegates
    // to `settle::repair::alias_size_band` - one rule for both seams,
    // ratio plus a per-article framing allowance - and the five rebuilds
    // pair one to one with the five losses. This is the acceptance test
    // for that row: do NOT weaken it back to an observation, for the
    // reason the sibling above gives. The control that must keep
    // FAILING is `a_chain_with_a_genuinely_lost_file_still_fails`.
    assert!(
        ok,
        "the payload landed byte-exact and every sidecar was rebuilt from \
         parity by a set this job's own set vouches for, but the job still \
         exits nonzero - a chain rebuild was not credited to the slot it is\n{log}"
    );
}

/// X5-11, first name layout. **MEASURED PASS 31 Aug 2026** - and kept as
/// the CONTROL for the sibling below, not as a result in its own right.
///
/// Without it, a red in the other layout could as easily mean "the chain
/// does not work at all" as "the chain does not work in one order", and
/// those two want different fixes.
#[tokio::test(flavor = "multi_thread")]
async fn x5_11_a_known_set_completes_when_its_prerequisite_arrives_first() {
    if !have_par2() {
        eprintln!("x5_11: par2 unavailable - skipping");
        return;
    }
    let (_fx, log, ok, out) =
        run_chain_fixture("chainx511b", InnerOnWire::VolumesOnly, false).await;
    let landed = std::fs::read(out.join("movie.bin")).unwrap_or_default();
    eprintln!(
        "x5_11 [b-first]: rc ok={ok}, movie.bin {} bytes",
        landed.len()
    );
    assert_eq!(
        landed.len(),
        120_000,
        "[b-first] the chain does not complete even in the benign \
         order\n{log}"
    );
    // ASSERTED since 31 Aug 2026, and it was an `eprintln!` observation
    // before that for one measured reason: the pre-settle alias band
    // paired first-fit across the spare pool, so at three levels' worth
    // of colliding sizes a payload slot could take the spare a sidecar
    // slot needed and the sidecar was left uncovered - one slot
    // unexcused, and a chain that delivered every byte exiting nonzero.
    // `reconcile_obfuscated_aliases` now pairs global best-fit, so this
    // is the acceptance test for that row. Do NOT weaken it back to an
    // observation: a chain whose payload lands byte-exact and whose
    // sidecars were all rebuilt from parity has nothing left to report.
    assert!(
        ok,
        "[b-first] the payload landed byte-exact and every sidecar was \
         rebuilt from parity, but the job still exits nonzero - a slot \
         was handed the spare another slot fitted better\n{log}"
    );
}

/// X5-11, second name layout. **THE ROW DID NOT REPRODUCE** (measured
/// 31 Aug 2026) and this probe is landed as a PASS PIN with its limits
/// stated, which is a different and weaker thing than a clean bill.
///
/// The precondition is reached: only set A is identified in-stream, and
/// the log shows TWO non-activated disk sets applied - so C really is in
/// the census with its index packet missing, and B really does supply
/// that index inside the same pass. The payload then lands byte-exact in
/// both name layouts, which is the row's "correct result".
///
/// What is NOT established is that the loop was ever forced to meet C
/// BEFORE B, and the reason has been corrected since (see the module
/// note): visit order is a deterministic function of the on-disk names,
/// because `PacketCatalog::relist` sorts, so the two `c_first` layouts
/// really are two different orders rather than two samples of one. What
/// they do not establish is that either of them is the ADVERSE order -
/// which of the two names sorts first among C's hash names and B's
/// rebuilt real names is a fact about this fixture, not a control over
/// which set the loop reaches first in general.
///
/// So it stays a pass pin with its limits stated. If it ever goes red,
/// that is this row finally being met in the adverse order, and the fix
/// is the one already in the tree, extended: the fixpoint retries ids
/// that FAILED and not only ids not yet SEEN, which is exactly what
/// X5-11 asks for.
#[tokio::test(flavor = "multi_thread")]
async fn x5_11_a_known_set_is_retried_after_its_prerequisites_arrive() {
    if !have_par2() {
        eprintln!("x5_11 reverse: par2 unavailable - skipping");
        return;
    }
    let (_fx, log, ok, out) = run_chain_fixture("chainx511c", InnerOnWire::VolumesOnly, true).await;
    let landed = std::fs::read(out.join("movie.bin")).unwrap_or_default();
    eprintln!(
        "x5_11 [c-first]: rc ok={ok}, movie.bin {} bytes",
        landed.len()
    );
    assert_eq!(
        landed.len(),
        120_000,
        "[c-first] the set that names the payload was skipped for a \
         missing index packet, another set in the same pass then created \
         that packet, and nothing retried it\n{log}"
    );
    eprintln!("x5_11: exit-code observation only, ok={ok}");
}

/// The par2-of-par2 EXIT CODE row: a chain that delivers every byte must
/// exit ZERO.
///
/// Measured 31 Aug 2026 on the two-level chain, and again on the
/// three-level one above: the payload lands byte-exact and MD5-proved
/// and the run still ends `download incomplete: N file(s) with missing
/// segments`. The verdict counted every NZB slot whose articles were
/// refused - and in a post like this the SIDECAR slots are refused BY
/// CONSTRUCTION. The inner recovery set is posted under hash names, so
/// the plan gives it payload slots; the poster never intends those
/// articles to be the route the file arrives by, and the outer set
/// rebuilds them from parity. A wrong FAILURE verdict on a successful
/// job is the mirror of the wrong-success class this repo treats as its
/// most serious: it tells the user, and every *arr reading the exit
/// code, to fetch again a post that is complete on disk.
///
/// TWO LEVELS is the right depth for THIS row, which is the opposite of
/// the sibling rows above and worth stating so nobody "improves" it.
/// W4-12 needs a set that comes into existence DURING the late pass, and
/// two levels cannot produce one. This row needs only a chain whose
/// sidecars are refused and rebuilt - the shortest post that has one -
/// and a third level adds an independent defect (the pre-settle alias
/// band mis-pairs across two levels' packet sizes, written up in
/// research/RECONCILE-BAND-PAIRING-2026-08-31.md) that would make this
/// probe fail for a reason that is not its row.
///
/// Graded on the payload as well as the code, and that is the control:
/// without it a red would read as "the exit code is wrong" when the real
/// answer could be "nothing was delivered at all", and those want
/// opposite fixes.
#[tokio::test(flavor = "multi_thread")]
async fn a_chain_that_delivers_every_byte_exits_zero() {
    if !have_par2() {
        eprintln!("chain exit: par2 unavailable - skipping");
        return;
    }
    let (_fx, log, ok, out) = run_two_level_chain("chainexit", CHAIN_MEMBERS, None).await;
    for (name, want) in CHAIN_MEMBERS {
        let landed = std::fs::read(out.join(name)).unwrap_or_default();
        eprintln!("chain exit: {name} {} bytes", landed.len());
        assert_eq!(
            landed.len(),
            *want,
            "the chain did not deliver {name} at all\n{log}"
        );
    }
    assert!(
        ok,
        "every byte landed and the chain MD5-proved it, but the job still \
         reports the sidecar segments that never arrived for files it \
         rebuilt from parity\n{log}"
    );
}

/// The control that has to keep failing, and the reason this row is not
/// simply "stop counting refused slots".
///
/// The same chain plus one more obfuscated payload slot that NO set in
/// the post covers and that is wholly refused. Its bytes are genuinely
/// lost - nothing on disk is them and no parity anywhere can produce
/// them - so the job must still exit nonzero. A fix that credited a
/// refused slot on the strength of the post's SHAPE, rather than on a
/// proven rebuild uniquely assignable to that slot, passes the probe
/// above and fails this one.
///
/// 48,000 bytes, DELIBERATELY the same size as a member the chain does
/// rebuild, which makes this the strong version of the control rather
/// than the easy one. An obfuscated post gives a scanner nothing but
/// lengths to go on - `latesets::fits` and the pre-settle band either
/// side of it are ONE rule since 31 Aug 2026 and it is documented as a
/// sanity check and not an identity proof - so a size that collides
/// with a real rebuild is exactly the
/// shape that could talk this tier into crediting a loss with somebody
/// else's bytes. What refuses it is COUNTING, not naming: every pass
/// that excuses a short slot consumes one proven whole file and no
/// pass consumes one twice, so a post with one more short slot than
/// the chain proved files leaves at least one slot unaccounted
/// whichever way the bands happen to pair up. Here that is ten short
/// slots against nine proven files.
#[tokio::test(flavor = "multi_thread")]
async fn a_chain_with_a_genuinely_lost_file_still_fails() {
    if !have_par2() {
        eprintln!("chain exit control: par2 unavailable - skipping");
        return;
    }
    let (_fx, log, ok, out) = run_two_level_chain("chainexitc", CHAIN_MEMBERS, Some(48_000)).await;
    for (name, want) in CHAIN_MEMBERS {
        assert_eq!(
            std::fs::read(out.join(name)).unwrap_or_default().len(),
            *want,
            "the lost file cost the chain its own rebuild of {name}\n{log}"
        );
    }
    assert!(
        !ok,
        "a file no set in the post covers was refused whole, and the job \
         still reported success\n{log}"
    );
    assert!(
        log.contains("download incomplete"),
        "the failure must still be the missing-articles one\n{log}"
    );
}

/// The band defect: a chain whose rebuilt sidecar is SMALLER than yEnc's
/// own framing can hide in must still exit zero.
///
/// ONE member on purpose, which is the opposite of every other fixture
/// in this file and is the whole point. `par2 create` sizes its index
/// file from the number of members it describes, so a one-member set
/// puts the index at 648 bytes - and a 648-byte file posted in a single
/// article declares 788, which is 1.216x. Measured 31 Aug 2026 against
/// `reconcile_obfuscated_aliases` as it stood: the pure 1.2 ratio
/// refused that slot, and a job whose output was complete and MD5-proved
/// ended `repair succeeded, but 2 file(s) outside the PAR2 set are still
/// incomplete` with the rebuilt `setb.par2` sitting on disk beside the
/// verdict. Write-up: `research/RECONCILE-BAND-PAIRING-2026-08-31.md`.
///
/// yEnc's cost is 3.5% of the payload PLUS a fixed per-article framing,
/// so a ratio-only band reads a small file's framing as a proportional
/// overrun. It is graded here rather than in a unit test because the
/// 648/788 pair is a property of real `par2 create` output and a real
/// yEnc encoder, not of a number this suite could choose - the unit
/// tests beside `alias_size_band` pin the RULE, this pins the POST.
///
/// Graded on the payload as well as the code, for
/// [`a_chain_that_delivers_every_byte_exits_zero`]'s reason: without it
/// a red would read as "the exit code is wrong" when the real answer
/// could be "nothing was delivered at all".
#[tokio::test(flavor = "multi_thread")]
async fn a_one_member_chain_under_the_ratio_band_exits_zero() {
    if !have_par2() {
        eprintln!("chain band: par2 unavailable - skipping");
        return;
    }
    const ONE: &[(&str, usize)] = &[("movie.bin", 120_000)];
    let (_fx, log, ok, out) = run_two_level_chain("chainband", ONE, None).await;
    let landed = std::fs::read(out.join("movie.bin")).unwrap_or_default();
    eprintln!("chain band: rc ok={ok}, movie.bin {} bytes", landed.len());
    assert_eq!(
        landed.len(),
        120_000,
        "the one-member chain did not deliver its payload at all\n{log}"
    );
    assert!(
        ok,
        "every byte landed and the chain MD5-proved it, but a sidecar the \
         set rebuilt whole was refused an excuse because yEnc's fixed \
         per-article framing on a 648-byte file reads as a proportional \
         overrun\n{log}"
    );
}

/// The inner set's members. THREE of them, and both the count and the
/// spread of the sizes are load-bearing.
///
/// THE COUNT sizes the inner set's INDEX file, and that is what makes
/// this fixture grade its own row rather than a neighbour's. Every one
/// of the inner set's packet files has an NZB slot that is refused, and
/// those slots are excused before the late pass ever runs, by
/// `settle::repair::reconcile_obfuscated_aliases`, whose band WAS a pure
/// RATIO: the slot's declared yEnc bytes had to be at most 1.2x the
/// rebuilt file's length. yEnc overhead is not a ratio - it is about
/// 3.5% of the payload plus a fixed ~118 bytes of framing per article -
/// so the ratio was exceeded on any member under about 700 bytes.
/// Measured 31 Aug 2026: a ONE-member inner set has a 648-byte index
/// posted at 788 (1.216x), its slot was not excused, and the job failed
/// for that reason instead of this one. Three members put the index at
/// 1,244 bytes (1.13x).
///
/// That band defect is FIXED (`YENC_ARTICLE_FRAMING`, an additive
/// per-article allowance beside the ratio) and the one-member chain is
/// now a probe in its own right -
/// [`a_one_member_chain_under_the_ratio_band_exits_zero`]. Keep THIS
/// fixture at three members anyway: it is what separates the two rows,
/// so trimming it back would leave nothing grading the band and nothing
/// grading the spread below.
///
/// THE SPREAD is what makes the three losses decidable. `latesets::fits`
/// admits a rebuild against a slot declaring 0.9x its length up to
/// 1.2x plus a per-article framing allowance, so consecutive members
/// are kept a factor of two apart and no rebuild fits any slot but its
/// own. That ceiling was a flat 1.5x until 31 Aug 2026, and the factor
/// of two clears both - which is the point of choosing a spread rather
/// than a margin. It is not slack to spend: the sibling three-level
/// fixture's sidecar sizes are `par2 create`'s own and NOT chosen, and
/// its 42,008/52,076 pair is 1.24x apart, which the old ceiling could
/// not separate. See `w4_12_...`.
const CHAIN_MEMBERS: &[(&str, usize)] = &[
    ("movie.bin", 120_000),
    ("extras.bin", 48_000),
    ("notes.bin", 20_000),
];

/// The two-level chain: `members` covered by set B, B's own packet files
/// covered by set A, and only A on the wire.
///
/// `members` is a parameter and not [`CHAIN_MEMBERS`] itself because the
/// COUNT changes which row the fixture grades - `par2 create` sizes its
/// index file from the number of members it describes, so one member
/// puts that index under the alias band's per-article framing allowance
/// and three do not. Both are wanted, and each has a probe of its own
/// saying which.
///
/// A is identified in-stream and repairs B during the REPAIR phase, so
/// by the time the late pass takes its census B's packet files are on
/// disk under their real names and an ACTIVE set names them - which is
/// what makes B VOUCHED. Applying B then creates the members. Every one
/// of B's own slots, and every member's, is refused on the wire.
///
/// `lost` adds one more payload slot of that many bytes which NO set
/// covers and which is likewise wholly refused - the control's
/// genuinely-lost file.
async fn run_two_level_chain(
    tag: &str,
    members: &[(&'static str, usize)],
    lost: Option<usize>,
) -> (Fixture, String, bool, PathBuf) {
    let mut fx = Fixture::new(tag);
    let mut chaos = Chaos::default();

    let payloads: Vec<(&str, Vec<u8>)> = members
        .iter()
        .enumerate()
        .map(|(i, (name, len))| {
            let data = payloads::unique_payload(*len, 91 + i as u64);
            std::fs::write(fx.dir.join(name), &data).unwrap();
            (*name, data)
        })
        .collect();
    let set_b = create_par2(
        &fx,
        "setb",
        100,
        10_000,
        &members.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
    );
    for (name, _) in &payloads {
        std::fs::remove_file(fx.dir.join(name)).unwrap();
    }

    // A covers exactly B's packet files, so they have to be sitting in
    // the fixture directory while `par2 create` runs and gone again
    // before anything else looks.
    let b_names: Vec<String> = set_b
        .iter()
        .map(|p| {
            let n = p.file_name().unwrap().to_string_lossy().to_string();
            std::fs::copy(p, fx.dir.join(&n)).unwrap();
            n
        })
        .collect();
    let set_a = create_par2(
        &fx,
        "seta",
        100,
        10_000,
        &b_names.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    for n in &b_names {
        std::fs::remove_file(fx.dir.join(n)).unwrap();
    }

    for (i, (_, data)) in payloads.iter().enumerate() {
        chaos
            .missing
            .extend(post_obfuscated(&mut fx, &format!("pay{i}"), data, 40_000));
    }
    if let Some(n) = lost {
        let orphan = payloads::unique_payload(n, 37);
        chaos
            .missing
            .extend(post_obfuscated(&mut fx, "lostobf", &orphan, 40_000));
    }
    for (i, p) in set_b.iter().enumerate() {
        let data = std::fs::read(p).unwrap();
        chaos
            .missing
            .extend(post_obfuscated(&mut fx, &format!("bb{i}"), &data, 40_000));
    }
    for (i, p) in set_a.iter().enumerate() {
        let data = std::fs::read(p).unwrap();
        post_obfuscated(&mut fx, &format!("seta{i}"), &data, 40_000);
    }

    let (log, ok, out) = run_chain(&fx, chaos).await;
    (fx, log, ok, out)
}
