//! X5-10: one recovery set must not sweep a donor another set still
//! needs.
//!
//! Two recovery sets with DISJOINT file lists can still share a DONOR -
//! an unclaimed file on disk whose blocks happen to match members of
//! both. Set repair is sequential and, until 31 Aug 2026, once a set had
//! taken what it needs the majority-spent proof declared that donor
//! consumed and the per-set sweep deleted it immediately. The second set
//! then found nothing to adopt and failed with parity it could otherwise
//! have completed.
//!
//! ## Why the proof is not wrong, and the sweep TIMING is
//!
//! `adopt::proven_spent`'s damaged-twin arm excuses every slice the
//! repair rebuilt FROM PARITY - it has to, because that is exactly where
//! a damaged twin differs from the file it is a twin of - and requires a
//! MAJORITY of the target's slices to have been fed by this candidate.
//! Here 55 of A's 100 slices come from the donor and the other 45 are
//! rebuilt, so the arm never compares a single byte of the 41 blocks
//! that belong to B, and the donor is "proven" spent on evidence that
//! says nothing about them. Nothing INSIDE one set's repair can tell
//! that case from an honest twin: the discriminator is another set, and
//! the only place that exists is above the per-set loop. So the fix is
//! not a tighter proof, it is that nothing is deleted until every set -
//! the late ones in `get::latesets` included - has had its turn.
//!
//! This is NOT W4-15 (two sets over the SAME bytes under different
//! names) and not the multi-set row: here the two targets have nothing
//! in common. Only the third file, which belongs to neither set's file
//! list, is shared - and it is deleted out from under the second set by
//! the first one's success.
//!
//! ## Why the arithmetic is exact
//!
//! Both targets are 100 blocks. The donor `C` carries 55 of A's blocks
//! at their own offsets and 41 of B's, disjoint, plus a unique block 0
//! so its first 16 KiB matches neither target and it cannot be adopted
//! whole. A is given exactly 45 recovery blocks and B exactly 59:
//!
//! * A needs 100 = 55 adopted from C + 45 parity - exact, no slack.
//! * B needs 100 = 41 adopted from C + 59 parity - exact, no slack.
//!
//! So each set can be repaired if and only if it still has C. There is
//! no margin in either direction, which is what makes the outcome a
//! statement about the sweep rather than about how much parity happened
//! to be lying around.
//!
//! ## The RUNS loop, and a correction to why it is here
//!
//! The capability round reported this row as NONDETERMINISTIC and
//! blamed set visit order: "`disk_sets_scoped` orders sets by first
//! sighting over `nested::walk_candidates`, which is a plain
//! `std::fs::read_dir` with NO SORT". **That diagnosis is wrong and is
//! recorded here so nobody re-derives it.** `disk_sets_scoped` builds a
//! `PacketCatalog`, and `PacketCatalog::relist` sorts its file list by
//! path before anything walks it, so set order has always been a
//! deterministic function of the names on disk. Measured on the fix
//! commit's own box: the baseline lost `b.bin` in 12 of 12 runs, every
//! one of them. Whatever varied on the round's box (it reported 6 of 6
//! then 3 of 6) was not the census.
//!
//! The `RUNS` loop stays anyway, for the reason that survives the
//! correction: a probe whose subject is "one set's success destroys
//! another set's input" is exactly the shape a per-test retry launders
//! into "N passed (1 flaky)" at exit 0, which is how a 4,666-second
//! deadlock once came out of CI green. Six runs of a two-second fixture
//! is cheap insurance against a residual ordering effect nobody has
//! ruled out - it must NOT be reduced to a one-shot with `retries`
//! covering for it.
//!
//! A child of [`super`] rather than a sibling of `e2e.rs`: `e2e.rs` sits AT
//! its size-gate baseline with no room for another `mod` line, and this row
//! belongs to that parent's subject anyway.

use super::*;
use crate::payloads;

const BLK: usize = 16_384;
const NBLK: usize = 100;

/// One block of content unique to `(tag, i)`.
///
/// Built on the shared [`payloads::unique_payload`] rather than a local
/// generator, and the shared one's guarantee is exactly what this row
/// needs: no repeated PAR2 block at any alignment, within one output or
/// across two seeds. A generator whose seeds are shifted windows of one
/// stream cannot support "these blocks are shared and those are not",
/// which is the whole construction here. The two indices are folded into
/// one seed so every (tag, block) pair draws its own sequence.
fn block(tag: u64, i: usize) -> Vec<u8> {
    payloads::unique_payload(
        BLK,
        tag.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ (i as u64).wrapping_mul(0xD6E8_FEB8_6659_FD93),
    )
}

/// The three payloads. `a` and `b` are independent; `c` is the donor -
/// block 0 unique, then 55 of A's blocks and 41 of B's at their own
/// offsets, then 3 more unique ones.
fn payloads() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let a: Vec<Vec<u8>> = (0..NBLK).map(|i| block(1, i)).collect();
    let b: Vec<Vec<u8>> = (0..NBLK).map(|i| block(2, i)).collect();
    let mut c: Vec<Vec<u8>> = (0..NBLK).map(|i| block(3, i)).collect();
    // Indices 1..=55 carry A, 56..=96 carry B. Block 0 and 97..99 stay
    // unique, so the head window matches neither target.
    c[1..=55].clone_from_slice(&a[1..=55]);
    c[56..=96].clone_from_slice(&b[56..=96]);
    let flat = |v: &Vec<Vec<u8>>| v.iter().flatten().copied().collect::<Vec<u8>>();
    (flat(&a), flat(&b), flat(&c))
}

/// `par2 create` one set over `file` with an exact recovery-block count,
/// move the products out of the fixture directory, and return them with
/// the set id read off the index file.
fn make_set(
    fx: &Fixture,
    base: &str,
    recovery_blocks: u32,
    file: &str,
) -> Option<(Vec<u8>, Vec<(String, Vec<u8>)>)> {
    let st = Command::new("par2")
        .arg("create")
        .arg(format!("-c{recovery_blocks}"))
        .arg(format!("-s{BLK}"))
        .arg("-q")
        .arg(base)
        .arg(file)
        .current_dir(&fx.dir)
        .status();
    if !matches!(st, Ok(s) if s.success()) {
        return None;
    }
    let mut made: Vec<PathBuf> = std::fs::read_dir(&fx.dir)
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            (p.extension().is_some_and(|x| x == "par2")).then_some(p)
        })
        .collect();
    made.sort();
    let mut files = Vec::new();
    let mut id = None;
    for p in &made {
        let data = std::fs::read(p).unwrap();
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        if !name.contains(".vol") {
            id = nzbkit::par2::Par2Set::set_id_of(&data).map(|x| x.to_vec());
        }
        files.push((name, data));
        std::fs::remove_file(p).unwrap();
    }
    id.map(|i| (i, files))
}

/// Post one buffer under a HASH subject and a HASH yEnc name, so nothing
/// on the wire carries a real name and no set activates in-stream.
/// Returns the bracketed ids so a caller can refuse them.
fn post_obfuscated(fx: &mut Fixture, tag: &str, data: &[u8]) -> Vec<String> {
    let hash = format!("{tag}Qz7Wm4Vb");
    let segs = make_file_articles(&hash, data, 60_000, tag, &mut fx.articles);
    let ids = segs.iter().map(|(id, _, _)| format!("<{id}>")).collect();
    fx.nzb_files.push((hash, segs));
    ids
}

/// How many times the fixture is run. Every run must deliver both
/// targets. Kept at six after the module note's correction: the failure
/// was deterministic here, so the samples buy nothing against THAT
/// reading and everything against a residual ordering effect - and the
/// loop costs a few seconds.
const RUNS: usize = 6;

/// One run of the fixture. Returns the two delivered lengths.
///
/// There is no order parameter and no set-id search, deliberately: which
/// of two hash-named packet files sorts first is not something this
/// fixture can meaningfully choose, and the row is about the SWEEP and
/// not about the order - either order must deliver both targets.
async fn run_once(tag: &str) -> (Fixture, String, PathBuf) {
    let (a, b, c) = payloads();
    let mut fx = Fixture::new(tag);

    std::fs::write(fx.dir.join("a.bin"), &a).unwrap();
    std::fs::write(fx.dir.join("b.bin"), &b).unwrap();
    // The set id is returned but unused: it does not decide visit
    // order (unsorted `read_dir` does), so nothing here reads it.
    let (_, fa) = make_set(&fx, "seta", 45, "a.bin").expect("par2 create a");
    let (_, fb) = make_set(&fx, "setb", 59, "b.bin").expect("par2 create b");
    std::fs::remove_file(fx.dir.join("a.bin")).unwrap();
    std::fs::remove_file(fx.dir.join("b.bin")).unwrap();

    let mut chaos = Chaos::default();
    // Both targets are WHOLLY missing: parity plus the shared donor are
    // the only way either can exist.
    chaos.missing.extend(post_obfuscated(&mut fx, "aobf", &a));
    chaos.missing.extend(post_obfuscated(&mut fx, "bobf", &b));
    // The donor arrives, unclaimed - no set's file list names it.
    post_obfuscated(&mut fx, "cobf", &c);
    for (i, (_, data)) in fa.iter().chain(fb.iter()).enumerate() {
        post_obfuscated(&mut fx, &format!("p{i}"), data);
    }

    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, _ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || run_get(&cfg, &nzb, &out, &[])
    })
    .await
    .unwrap();
    if std::env::var("DONORSHARE_DUMP_LOG").is_ok() {
        eprintln!("==== run log ====\n{log}\n==== end ====");
    }
    (fx, log, out)
}

/// X5-10: a donor shared by two sets with disjoint file lists must
/// survive the first set's repair.
///
/// **MEASURED RED 31 Aug 2026.** The log names the mechanism in one
/// line: the set covering `a.bin` completes with "55 block(s) adopted
/// from cobf...", the next line is "removed 1 spent source file(s) the
/// repair adopted from (to the Trash)", and `b.bin` - which needed 41
/// blocks of that same donor plus its own 59 parity - is delivered at
/// zero bytes. Neither set's file list ever named the donor.
///
/// The fix the row asks for is the invariant the disk all-set path in
/// `get/settle.rs` already demonstrates: a shared candidate may be
/// consumed only once EVERY set has finished using it.
///
/// **CLOSED 31 Aug 2026** and this is a live pin now. The sweep is
/// DEFERRED: `fetch_and_repair` records what a repair proved spent
/// instead of deleting it, and `settle_with_set` sweeps once the
/// late-set pass has also run - so the donor is still there when the
/// second set asks for it. `get::latesets` defers its own the same way,
/// for the same reason, across its whole fixpoint.
///
/// The `RUNS` loop stays, and so does everything the module note says
/// about why - but see that note's correction: on the fix commit's own
/// box the baseline lost `b.bin` in 12 of 12 runs, deterministically,
/// because set visit order was never the raw `read_dir` order the
/// original reading blamed (`PacketCatalog::relist` sorts). Sampling is
/// cheap insurance rather than the instrument it was thought to be.
#[tokio::test(flavor = "multi_thread")]
async fn x5_10_a_shared_donor_survives_every_sets_repair() {
    if !have_par2() {
        eprintln!("x5_10: par2 unavailable - skipping");
        return;
    }
    let (a, b, _) = payloads();
    let mut lost = Vec::new();
    let mut last_log = String::new();
    for i in 0..RUNS {
        let (fx, log, out) = run_once(&format!("donorshare{i}")).await;
        let got_a = std::fs::read(out.join("a.bin")).unwrap_or_default();
        let got_b = std::fs::read(out.join("b.bin")).unwrap_or_default();
        // The Fixture owns the scratch guard; read before it drops.
        drop(fx);
        eprintln!(
            "x5_10 run {i}: a.bin {} bytes, b.bin {} bytes",
            got_a.len(),
            got_b.len()
        );
        if got_a != a || got_b != b {
            lost.push(i);
            last_log = log;
        }
    }
    assert!(
        lost.is_empty(),
        "{} of {RUNS} runs lost a target - the donor both sets needed was \
         swept after the first one used it (runs {lost:?})\n{last_log}",
        lost.len()
    );
}
