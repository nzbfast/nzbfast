//! Hostile PAR2 GEOMETRY - a recovery set whose numbers are the attack.
//!
//! Split out of `e2e_norar` on 30 Aug 2026 because that module reached
//! its 3,000-line ceiling: two lanes appended on the same day and the
//! union went 173 lines over. This is the subject seam, not a slice -
//! every row here is a set that parses cleanly and whose DECLARED
//! geometry (a member's length, a slice size) is a lie or an extreme,
//! which is a different question from `e2e_norar`'s subject of names.
//!
//! A sibling-dir child of e2e.rs (the `e2e_sniffedpar2` pattern), so
//! helpers come via `super::*`. The three PAR2 packet-editing helpers
//! stay in `e2e_norar` and are reached through `super::e2e_norar::` -
//! copying them here is how two spellings of one packet walker start,
//! and its module header explains why a patched-then-resealed set is a
//! real creator's output rather than corruption.

use super::e2e_norar::{filedesc_name, packets, reseal, run_norar};
use super::*;

// ---------------------------------------------- hostile PAR2 geometry
//
// M4-23/24/25 of the no-RAR capability matrix cited in this module's
// header each PREDICTED a failure and each measures CLEAN, so
// what lands here are PASS PINS: the point is that the next reader
// takes the measurement off the shelf instead of deriving it a fourth
// time. M4-23 (reconstruct with zero payload posts) is pinned in
// e2e.rs by par_only_post_reconstructs_two_files_from_one_set; the
// decoder half of M4-25 - the 262144-cell shape no creator will emit -
// is pinned in nzbkit's par2::tests. The two rows below had no pin
// anywhere on main.

/// Rewrite the declared LENGTH of every FileDesc named `name`, resealing
/// each packet. The stored file id is deliberately NOT recomputed: it is
/// what Main's list names, and readers key Main/FileDesc/IFSC by the
/// STORED id, so the set stays internally consistent and simply lies
/// about how big the member is. Returns how many packets moved - the
/// critical packets repeat in every volume, so normally > 1.
fn patch_filedesc_length(data: &mut Vec<u8>, name: &str, length: u64) -> usize {
    let mut hits = 0;
    for (start, len, ptype) in packets(data) {
        if &ptype != b"PAR 2.0\0FileDesc" || filedesc_name(data, start, len) != name {
            continue;
        }
        data[start + 112..start + 120].copy_from_slice(&length.to_le_bytes());
        reseal(data, start, len);
        hits += 1;
    }
    hits
}

/// [`add_par2_patched`] with an explicit SLICE size. That helper cannot
/// set `-s` and its signature is left alone on purpose - six sibling
/// tests call it and several lanes are appending to this file at once.
fn add_par2_sliced(
    fx: &mut Fixture,
    slice: u32,
    redundancy: u32,
    files: &[&str],
    patch: impl Fn(&mut Vec<u8>),
) -> bool {
    let st = Command::new("par2")
        .arg("create")
        .arg(format!("-s{slice}"))
        .arg(format!("-r{redundancy}"))
        .arg("-q")
        .arg("hostileset")
        .args(files)
        .current_dir(&fx.dir)
        .status();
    if !st.map(|s| s.success()).unwrap_or(false) {
        return false;
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
        let mut blob = std::fs::read(&p).unwrap();
        patch(&mut blob);
        let tag = format!("{}-{}", name.replace('.', "_"), fx.nzb_files.len());
        let segs = make_file_articles(&name, &blob, 40_000, &tag, &mut fx.articles);
        fx.nzb_files.push((name, segs));
        std::fs::remove_file(&p).unwrap();
    }
    true
}

/// The biggest regular file anywhere under `out`, by its ALLOCATED
/// length rather than by the bytes it reads back. `out_tree` above reads
/// content, and a `set_len` to a length nobody wrote is SPARSE - it
/// would read back as the honest zeros it never stored, which is exactly
/// the shape M4-24 has to be able to see.
fn out_biggest(out: &Path) -> (u64, String) {
    fn walk(dir: &Path, best: &mut (u64, String)) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for p in rd.flatten().map(|e| e.path()) {
            if p.is_dir() {
                walk(&p, best);
            } else if let Ok(m) = p.metadata()
                && m.len() > best.0
            {
                *best = (m.len(), p.display().to_string());
            }
        }
    }
    let mut best = (0, String::new());
    walk(out, &mut best);
    best
}

/// M4-24: a FileDesc LENGTH BOMB. The set declares a member far larger
/// than the bytes actually posted, so verification prices the difference
/// as missing and reconstruction is asked to recreate a file that never
/// existed at that size. The row predicted three things: that the engine
/// would price the lie as missing, that it might `set_len` the target,
/// and that it might run recovery for a file that was never that big
/// (`volume_prealloc_cap` bounds VOLUMES, not a payload reconstruct).
///
/// The FIRST of those is CONFIRMED and the other two are REFUTED, which
/// is sharper than the wave-5 round's flat "not confirmed" and is what
/// this pins. The lie really is priced - the run logs `32760/32768
/// blocks bad` for a 16 MiB claim at a 512-byte slice, every invented
/// block of it - and then nothing acts on it: the job fails honestly and
/// the biggest thing on disk is the honest 4096 bytes.
///
/// The defence is NOT length-specific, and that is the useful part. It
/// is the ordinary shortfall gate - blocks needed exceed blocks carried
/// - which is right, because a length bomb is indistinguishable from a
/// large file almost none of which was posted. Measured by mutation on
/// 30 Aug 2026, THREE layers refuse it independently and each alone is
/// enough: `par2repair`'s `by_exp.len() < needed`, `check_repair_dim`'s
/// 8192-block matrix cap, and `load_selected_recovery` returning None.
/// So the size assertion below cannot be falsified by removing any one
/// of them - the block-count assertion is the one that bites, and
/// disabling the first layer is what reddens it.
///
/// The lie is 16 MiB rather than the row's 1 GiB deliberately - this box
/// shares a disk with several lanes - and 16 MiB is already four
/// thousand times the post, so anything that followed the declared
/// length would trip the same ceiling a gigabyte would. That ceiling is
/// 64 KiB against a measured maximum of exactly 4096, so it bounds
/// FOLLOWING THE DECLARATION rather than pinning a byte count a kept
/// recovery volume could legitimately move.
#[tokio::test(flavor = "multi_thread")]
async fn a_filedesc_length_bomb_never_materializes_the_lie() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    const LIE: u64 = 16 << 20;
    let data = payload(4096, 13);
    let mut fx = Fixture::new("norarlenbomb");
    std::fs::write(fx.dir.join("Small.Real.bin"), &data).unwrap();
    let patched = std::cell::Cell::new(0usize);
    assert!(add_par2_sliced(
        &mut fx,
        512,
        20,
        &["Small.Real.bin"],
        |blob| patched.set(patched.get() + patch_filedesc_length(blob, "Small.Real.bin", LIE)),
    ));
    // Guard the guard: an inert patch leaves an ordinary honest set, and
    // this row would pass having tested nothing at all.
    assert!(
        patched.get() > 0,
        "no FileDesc was patched - fixture is inert"
    );
    // Posted under its REAL name, which is the route the row names first
    // ("exact-name or md5-16k claims the short file") and the only one
    // that reaches the repair machinery at all. Obfuscated, the live tier
    // matches on (length, md5_16k) and the 16 MiB lie simply fails to
    // match, so nothing is ever claimed and this row would be green for a
    // reason that has nothing to do with the bomb - verified by mutation:
    // a prealloc of `t.file.length` inserted into par2repair's damaged
    // loop was INVISIBLE to the obfuscated fixture and is caught by this
    // one.
    fx.add_file("Small.Real.bin", &data, 4096);

    let (log, ok, out) = run_norar(&fx).await;
    let biggest = out_biggest(&out);
    eprintln!("m4_24: rc ok={ok}, biggest output = {biggest:?}");

    // Reached-guard AND the falsifiable half: the shortfall verdict has
    // to have been the thing that stopped this, priced at the lie.
    // Without it an inert run - one that never got as far as repair -
    // would satisfy every assertion below by doing nothing at all.
    //
    // The price is the lie MINUS the eight blocks that really were
    // posted, and pinning THAT is sharper than the round number this
    // asserted until 30 Aug 2026. Before M4-37 the honest 8-entry IFSC
    // was dropped outright for disagreeing with the declared length, so
    // the member had no per-block evidence and was priced whole;
    // `par2::fit_ifsc` now keeps the entries the packet paid for and
    // fills the rest of the grid with `BlockCheck::UNPROVEN`, so the
    // eight real blocks verify and only the 32760 invented ones are
    // charged. Both directions still bite: an inert run prices nothing
    // at all, and a run that FOLLOWED the declaration would have to
    // charge every one of the 32768.
    let posted = (data.len() / 512) as u64;
    let damaged = LIE / 512 - posted;
    assert!(
        log.contains(&format!("{damaged}/{} blocks bad", LIE / 512)),
        "the {LIE}-byte claim was not priced as {damaged} missing blocks \
         over {posted} posted ones\n{log}"
    );
    // The refusal is the POST-ADOPTION shortfall, and since follow-up
    // 13a-1 (31 Aug 2026) it is reached BEFORE any recovery is bought -
    // so the line to look for is the probe's, not the post-fetch native
    // pass's. Same gate, same arithmetic, same figure; earlier.
    //
    // This row is also the sharpest live instance of what that reorder
    // is worth, and of follow-up 13a-2's complaint. The arm that falls
    // through here is `repeated_block_donor_possible`, on a set whose
    // damage is 32,758 blocks that were never posted - the predicate
    // cannot tell WHICH member is damaged, so it opened a fetch that
    // could not possibly find anything. It used to buy both declared
    // recovery blocks on the strength of that guess and then refuse
    // anyway; it now scans, prices the lie at the same 32,760, and buys
    // NOTHING. So the second assertion is the falsifiable half: revert
    // the reorder and this run pays for recovery before failing.
    assert!(
        log.contains(&format!(
            "adoption scan first: {damaged} block(s) still missing"
        )),
        "the shortfall gate is not what refused this run\n{log}"
    );
    assert!(
        !log.contains("→ fetching") && !log.contains("repair short - fetching all"),
        "a length bomb the scan cannot help with must buy no recovery \
         at all\n{log}"
    );
    assert!(
        !ok,
        "a post whose FileDesc lies by {LIE} bytes reported SUCCESS\n{log}"
    );
    assert!(
        biggest.0 <= 64 << 10,
        "a FileDesc declaring {LIE} bytes over a 4 KiB post left {} bytes \
         at {} - the declared length is being materialised\n{log}",
        biggest.0,
        biggest.1
    );
}

/// M4-25, creator half. `parse_main` accepts any `block_size % 4 == 0`
/// with no floor, so a modest member can declare hundreds of thousands
/// of blocks - one IFSC entry and one live-verify cell each. The row
/// predicted the verifier would blow up or take minutes.
///
/// MEASURED CLEAN (wave-5 round, 30 Aug 2026): a 4 KiB payload at 4-byte
/// blocks completes in 0.34 s and lands byte-exact.
///
/// This is the end-to-end arm and it is deliberately at the SMALL end of
/// the shape - 4 KiB at 4-byte blocks is 1024 cells, which proves the
/// geometry reaches the live tier without melting a box that routinely
/// carries six concurrent suites. The hostile end of it (262144 cells)
/// is a decoder question, not a wire one, and par2cmdline refuses to
/// create it at all, so it is pinned in nzbkit's par2::tests instead.
///
/// That decoder pin holds the DISJUNCTION the row allows (refuse below a
/// floor, or accept and bound); this one deliberately does not. A floor
/// added later stops a legitimate small-slice post being deobfuscated at
/// all, so it should redden here and be decided rather than land quietly
/// - verified 30 Aug 2026: a 2048-byte floor in `parse_main` fails this.
#[tokio::test(flavor = "multi_thread")]
async fn a_four_byte_block_size_post_still_lands_byte_exact() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let data = payload(4096, 91);
    let mut fx = Fixture::new("norartinyblk");
    std::fs::write(fx.dir.join("Tiny.Blocks.bin"), &data).unwrap();
    if !add_par2_sliced(&mut fx, 4, 10, &["Tiny.Blocks.bin"], |_| {}) {
        // The CREATOR side is bounded too - also a correct answer, and
        // the decoder arm in nzbkit covers the shape either way.
        eprintln!("skipping: par2cmdline refuses -s4");
        return;
    }
    std::fs::remove_file(fx.dir.join("Tiny.Blocks.bin")).unwrap();
    fx.add_file_obfuscated("Sd8kNc17Vj", "Sd8kNc17Vj", &data, 4096);

    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "a 4-byte-block post failed:\n{log}");
    let got = std::fs::read(out.join("Tiny.Blocks.bin"))
        .unwrap_or_else(|e| panic!("payload missing under its FileDesc name: {e}\n{log}"));
    assert!(got == data, "payload not byte-exact\n{log}");
}
