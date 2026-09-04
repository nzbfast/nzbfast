//! What a PAR2 packet is allowed to assert about a file - the two rows
//! of cursor's third extreme pass that live under `crates/nzbkit-base/src/par2.rs`.
//!
//! M4-37: an IFSC whose entry count disagrees with the FileDesc used to
//! be DROPPED, which left the file with no per-block evidence at all.
//! One flipped byte then failed the whole-file MD5, no slice could be
//! proven present, and a repair that needed a handful of recovery blocks
//! needed every block the file has. `par2::fit_ifsc` reconciles the
//! packet to the declared grid instead - a long list is trimmed to the
//! slices the file actually has, a short one keeps its prefix and the
//! rest is `BlockCheck::UNPROVEN`, which nothing can satisfy.
//!
//! M4-38 has no e2e leg here on purpose: a forged file id is decided
//! inside the two packet readers, and both are pinned where they live -
//! `par2.rs`'s `a_forged_file_id_never_beats_the_descriptor_that_binds_it`
//! drives BOTH arrival orders, which an e2e cannot, and
//! `par2repair::unit_tests`' `a_forged_file_id_does_not_take_another_files_main_slot`
//! drives the directory catalog.
//!
//! A CHILD of `e2e_norar` rather than more rows in it, and not a
//! sibling of it either: that file was 2,658 of its 3,000 size-gate
//! lines on 30 Aug 2026 with a dozen wave-4 lanes appending to it at
//! once, and `tests/e2e.rs` had ONE line of margin under its own
//! baseline, so the `mod` line had nowhere else to go. Fixture builders
//! come from the parent, everything else from `super::super::*`.

use super::super::*;
use super::{add_par2_patched, filedesc_name, packets, reseal};

const TYPE_FILEDESC: &[u8; 16] = b"PAR 2.0\0FileDesc";
const TYPE_IFSC: &[u8; 16] = b"PAR 2.0\0IFSC\0\0\0\0";

/// Add (`delta > 0`) or drop (`delta < 0`) that many 20-byte entries
/// from every IFSC packet describing `name`, keeping each packet
/// otherwise valid - length field rewritten, packet MD5 resealed - so
/// the ONLY thing wrong with the set is that the checksum list and the
/// descriptor disagree about how many slices the file has. Returns how
/// many packets moved; critical packets repeat in every volume, so a
/// full set is normally several.
///
/// Grown entries are copies of the packet's last one. Their content
/// cannot matter: they describe slices past the file's end, so nothing
/// ever hashes bytes to compare against them.
fn resize_ifsc(data: &mut Vec<u8>, name: &str, delta: isize) -> usize {
    let Some(fid) = packets(data).into_iter().find_map(|(start, len, ptype)| {
        (&ptype == TYPE_FILEDESC && filedesc_name(data, start, len) == name)
            .then(|| <[u8; 16]>::try_from(&data[start + 64..start + 80]).unwrap())
    }) else {
        return 0;
    };
    // Back to front, so the offsets recorded above stay valid as the
    // packets ahead of them change length.
    let mut spans: Vec<(usize, usize)> = packets(data)
        .into_iter()
        .filter(|&(s, l, t)| &t == TYPE_IFSC && l >= 84 && data[s + 64..s + 80] == fid)
        .map(|(s, l, _)| (s, l))
        .collect();
    spans.reverse();
    let hits = spans.len();
    for (s, l) in spans {
        let entries = (l - 80) / 20;
        let want = entries.saturating_add_signed(delta).max(1);
        let new_len = 80 + want * 20;
        if want > entries {
            let last: Vec<u8> = data[s + l - 20..s + l].to_vec();
            let mut fill = Vec::new();
            for _ in entries..want {
                fill.extend_from_slice(&last);
            }
            data.splice(s + l..s + l, fill);
        } else {
            data.drain(s + new_len..s + l);
        }
        data[s + 8..s + 16].copy_from_slice(&(new_len as u64).to_le_bytes());
        reseal(data, s, new_len);
    }
    hits
}

/// Post `fx` at a mock server and run one `get`, with `chaos` applied.
async fn run(fx: &Fixture, chaos: Chaos) -> (String, bool, PathBuf) {
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
    (log, ok, out)
}

/// One damaged article on this fixture's only payload file. Ids are
/// `<{tag}-{part}@mock>` with `tag` from `Fixture::add_file` and parts
/// numbered from 1; part 3 of eight is mid-file, which is the shape the
/// row is about - a whole-file MD5 cannot localize it.
fn corrupt_part_3(tag: &str) -> Chaos {
    Chaos {
        corrupt: std::iter::once(format!("<{tag}-3@mock>")).collect(),
        ..Chaos::default()
    }
}

/// Strip the recovery VOLUMES out of a posted set, leaving the index -
/// the manifest-only shape `add_par2_index_only` posts, with zero
/// recovery blocks on the wire, so nothing can repair its way past a
/// wrong verdict. Composed here rather than by growing another
/// parameter onto the shared builders, which a dozen wave-4 lanes are
/// appending to at once.
fn drop_recovery_volumes(fx: &mut Fixture) -> usize {
    let mut dropped = 0;
    let mut kept = Vec::new();
    for (name, segs) in std::mem::take(&mut fx.nzb_files) {
        if name.contains(".vol") && name.ends_with(".par2") {
            for (id, _, _) in &segs {
                fx.articles.remove(&format!("<{id}>"));
            }
            dropped += 1;
        } else {
            kept.push((name, segs));
        }
    }
    fx.nzb_files = kept;
    dropped
}

/// M4-37, the long half. par2cmdline slices a 300 KB payload into 1,974
/// blocks of 152 bytes, and `-r20` posts 395 recovery blocks; one dead
/// 40 KB article is ~264 of those blocks, comfortably inside 395. Add
/// ONE surplus entry to the IFSC - a checksum for a slice the file does
/// not have - and before the fix the whole packet went in the bin: the
/// file could then only be priced whole, all 1,974 blocks of it, and 395
/// recovery blocks cannot rebuild 1,974. The set is otherwise exactly
/// what par2cmdline wrote.
#[tokio::test(flavor = "multi_thread")]
async fn a_surplus_ifsc_entry_does_not_cost_the_file_its_block_grid() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("p2trustlong");
    let data = payload(300_000, 81);
    fx.add_file("Long.Ifsc.mkv", &data, 40_000);
    assert!(add_par2_patched(
        &mut fx,
        20,
        &["Long.Ifsc.mkv"],
        40_000,
        |blob| {
            assert!(
                resize_ifsc(blob, "Long.Ifsc.mkv", 1) > 0,
                "no IFSC packet to grow - the fixture proves nothing"
            );
        },
    ));
    let (log, ok, out) = run(&fx, corrupt_part_3("Long_Ifsc_mkv-0")).await;
    assert!(
        ok,
        "one surplus IFSC entry turned a one-article repair into a lost job:\n{log}"
    );
    let got = std::fs::read(out.join("Long.Ifsc.mkv"))
        .unwrap_or_else(|e| panic!("payload missing: {e}\n{log}"));
    assert!(got == data, "the repaired payload is not byte-exact\n{log}");
}

/// M4-37, the short half. The same set with the LAST IFSC entry
/// removed: slice 1,973 is now described by nothing, so it can never
/// read as proven - which is the hazard the old drop was written for,
/// and it survives - but the other 1,973 checks are the file's own and
/// are what price the damage. Repair therefore covers the dead article
/// plus that one unproven tail slice, not the whole file.
#[tokio::test(flavor = "multi_thread")]
async fn a_short_ifsc_still_prices_damage_by_the_prefix_it_does_cover() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("p2trustshort");
    let data = payload(300_000, 82);
    fx.add_file("Short.Ifsc.mkv", &data, 40_000);
    assert!(add_par2_patched(
        &mut fx,
        20,
        &["Short.Ifsc.mkv"],
        40_000,
        |blob| {
            assert!(
                resize_ifsc(blob, "Short.Ifsc.mkv", -1) > 0,
                "no IFSC packet to shorten - the fixture proves nothing"
            );
        },
    ));
    let (log, ok, out) = run(&fx, corrupt_part_3("Short_Ifsc_mkv-0")).await;
    assert!(
        ok,
        "a one-entry-short IFSC turned a one-article repair into a lost job:\n{log}"
    );
    let got = std::fs::read(out.join("Short.Ifsc.mkv"))
        .unwrap_or_else(|e| panic!("payload missing: {e}\n{log}"));
    assert!(got == data, "the repaired payload is not byte-exact\n{log}");
}

/// The regression the short half could have bought - a GUARD on the
/// fix, not a row: it passes before and after, and its job is to stay
/// passing. It is the one that would have hurt a healthy download: a
/// slice the IFSC never described reads Bad forever, so the block tier
/// alone would call a byte-perfect file damaged and a post with NO
/// recovery volumes would then fail over nothing at all. The whole-file
/// MD5 is what covers those bytes, and settle takes it (`live.rs`,
/// after the read-back loop). The recovery volumes are dropped from the
/// post deliberately: with none on the wire, nothing can repair its way
/// past a wrong verdict, so a pass here is the verdict and not a fix.
#[tokio::test(flavor = "multi_thread")]
async fn a_short_ifsc_over_a_perfect_download_is_not_damage() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("p2trustclean");
    let data = payload(300_000, 83);
    fx.add_file("Clean.Ifsc.mkv", &data, 40_000);
    assert!(add_par2_patched(
        &mut fx,
        20,
        &["Clean.Ifsc.mkv"],
        40_000,
        |blob| {
            resize_ifsc(blob, "Clean.Ifsc.mkv", -1);
        },
    ));
    assert!(
        drop_recovery_volumes(&mut fx) > 0,
        "no volumes were dropped - the post still carries recovery and \
         this test would pass on a repair rather than on a verdict"
    );
    let (log, ok, out) = run(&fx, Chaos::default()).await;
    assert!(
        ok,
        "an undamaged post failed because its IFSC stopped one slice short:\n{log}"
    );
    let got = std::fs::read(out.join("Clean.Ifsc.mkv"))
        .unwrap_or_else(|e| panic!("payload missing: {e}\n{log}"));
    assert!(got == data, "the payload is not byte-exact\n{log}");
}
