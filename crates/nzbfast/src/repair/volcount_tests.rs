//! [`super::credited_blocks`], and its wiring into
//! [`recovery_candidates`] - a helper nothing calls is the same green as
//! no helper at all.

use super::*;

/// The raw bytes a volume of `k` slices spends on those slices alone, at
/// `block_size` - `SLICE_PACKET_OVERHEAD` is 68 and the critical packets
/// every volume repeats are ON TOP of this.
///
/// Deliberately the SMALLEST figure a real volume's `bytes=` can carry:
/// the one-sidedness pin below is only worth something if it is driven
/// at the tightest end, and the NZB's own figure is the larger
/// yEnc-encoded one.
fn raw_slice_bytes(k: u64, block_size: u64) -> u64 {
    k * (block_size + 68)
}

/// An honest name over honest bytes is passed through untouched. The
/// control arm: a ceiling that bit here would be changing every healthy
/// post in the world.
#[test]
fn an_honest_volume_keeps_the_count_its_name_declares() {
    assert_eq!(
        credited_blocks("rel.vol000+64.par2", raw_slice_bytes(64, 384_000), 384_000),
        Some(64)
    );
}

/// THE DEFECT. A name declaring more slices than the volume's own bytes
/// could ever hold is credited with what the bytes allow and no more.
#[test]
fn a_name_claiming_more_blocks_than_the_bytes_can_hold_is_held_to_the_bytes() {
    // 2,000-byte blocks and a 41,000-byte body: 20 slices could fit, and
    // the name says nine hundred thousand.
    assert_eq!(
        credited_blocks("rel.vol9000+900000.par2", 41_000, 2_000),
        Some(20)
    );
}

/// `par2_vol_count`'s own cap is a different fix for a different
/// question (an overflowing ADDEND), and it leaves the whole range below
/// it credited on a filename's word. Pinned so nobody reads that cap as
/// covering this.
#[test]
fn the_declared_count_cap_alone_leaves_a_lie_thirty_two_times_par2s_maximum() {
    // Just inside `par2_vol_count`'s 1 << 20 cap, so the name parses.
    let declared = vol_count_from_name("rel.vol0+1048576.par2");
    assert_eq!(declared, Some(1 << 20));
    assert_eq!(
        credited_blocks("rel.vol0+1048576.par2", 41_000, 2_000),
        Some(20)
    );
}

/// ONE-SIDEDNESS, which is what licenses applying the ceiling with no
/// guard in front of it: over every block size and slice count this
/// repo's fixtures and real posts reach, an honest volume's count
/// survives. If this can be made to fail, the ceiling can push a
/// repairable post into a premature `shortfall_is_final`.
#[test]
fn the_ceiling_can_never_fall_below_an_honest_volumes_own_count() {
    for &bs in &[4u64, 76, 2_000, 4_096, 40_000, 384_000, 1 << 20] {
        for &k in &[1u64, 2, 13, 64, 395, 4_000, 32_768] {
            let name = format!("rel.vol0+{k}.par2");
            let k = usize::try_from(k).unwrap();
            assert_eq!(
                credited_blocks(&name, raw_slice_bytes(k as u64, bs), bs),
                Some(k),
                "an honest {k}-slice volume at block size {bs} lost blocks to the ceiling"
            );
        }
    }
}

/// A record with no `bytes=` is UNSIZED, not empty - sizing it as empty
/// would put a floor where the ceiling belongs and credit a real volume
/// with nothing.
#[test]
fn a_volume_whose_record_carries_no_bytes_keeps_its_declared_count() {
    assert_eq!(credited_blocks("rel.vol000+64.par2", 0, 384_000), Some(64));
}

/// An unreadable block size is the same mistake one layer out: with
/// `max_recovery_blocks` answering 0 by contract, a ceiling applied here
/// would zero EVERY volume in the post at once.
#[test]
fn an_unreadable_block_size_keeps_the_declared_count() {
    assert_eq!(credited_blocks("rel.vol000+64.par2", 1 << 30, 0), Some(64));
}

/// A name that declares nothing is handed straight back as `None` so the
/// caller reaches its size estimate exactly as it did before this
/// existed - the obfuscated post's whole road.
#[test]
fn a_name_that_declares_no_count_is_left_to_the_callers_estimate() {
    assert_eq!(credited_blocks("rel.par2", 41_000, 2_000), None);
    assert_eq!(credited_blocks("rel.vol-10.par2", 41_000, 2_000), None);
    // Past `par2_vol_count`'s cap, so the name declares nothing at all.
    assert_eq!(
        credited_blocks("rel.vol0+1048577.par2", 41_000, 2_000),
        None
    );
}

fn pset(block_size: u64) -> nzbkit::par2::Par2Set {
    nzbkit::par2::Par2Set {
        recovery_set_id: [0u8; 16],
        block_size,
        files: vec![nzbkit::par2::Par2File {
            file_id: [1u8; 16],
            name: "Repair.Me.mkv".to_string(),
            length: 1 << 20,
            md5: [0u8; 16],
            md5_16k: [0u8; 16],
            blocks: Vec::new(),
        }],
        nonrecovery: Vec::new(),
        recovery_blocks_seen: 0,
    }
}

/// One `<file>` per (name, bytes), each with one segment - the caller
/// reads `kind()`, `filename_hint()` and `bytes()` and nothing else.
/// `vol_affinity_tests`' own builder fixes the segment size, and the
/// whole question here is what a volume's BYTES allow.
fn nzb_sized(files: &[(&str, u64)]) -> Nzb {
    let mut x = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for (i, (n, bytes)) in files.iter().enumerate() {
        x.push_str(&format!(
            "<file poster=\"a@b\" date=\"1\" subject=\"&quot;{n}&quot; yEnc (1/1)\">\n\
             <groups><group>alt.bin</group></groups>\n<segments>\n\
             <segment bytes=\"{bytes}\" number=\"1\">seg{i}@h</segment>\n\
             </segments>\n</file>\n"
        ));
    }
    x.push_str("</nzb>\n");
    Nzb::parse(x.as_bytes()).expect("fixture NZB parses")
}

/// THE WIRING, and the reason the arithmetic pins above are not enough:
/// a helper the candidate loop does not call leaves `have` exactly as
/// inflated as it was.
///
/// Nothing here is affine to `Repair.Me.mkv`, and the output directory
/// does not exist, so the none-affine fallback fires and the whole list
/// comes back - which is the shape the wave-4 matrix read measured, and
/// the shape in which the filter is not a second line of defence.
#[test]
fn the_candidate_loop_credits_the_bytes_and_not_the_name() {
    let set = pset(2_000);
    let out = std::env::temp_dir().join("nzbfast-volcount-no-such-dir");
    let n = nzb_sized(&[
        ("rel.vol000+20.par2", raw_slice_bytes(20, 2_000)),
        ("rel.vol9000+900000.par2", 41_000),
    ]);
    let got = recovery_candidates(&n, &out, &set, &[], &[]);
    let counts: Vec<usize> = got.iter().map(|v| v.1).collect();
    assert_eq!(
        counts,
        vec![20, 20],
        "the second volume's name claims 900,000 slices in 41,000 bytes \
         and the fold that gates `shortfall_is_final` believed it"
    );
}

/// The knapsack half, which is the harm a `have` figure alone does not
/// show. [`pick_volumes`] is a byte-minimizing subset cover, so a name
/// declaring a block count its body could not possibly hold satisfies
/// ANY target on its own and the honest parity is never bought at all.
/// With the ceiling in place the impostor can cover no more than its own
/// bytes allow, so a target past that forces real volumes into the buy.
///
/// A STATED LIMIT rather than a claim this does not earn: the ceiling is
/// `bytes / block_size`, which is `block_size` bytes per credited block,
/// while an honest volume spends `block_size + 68` plus its critical
/// packets - so a clamped impostor is still marginally the cheapest row
/// per slice and can still be SELECTED. What it can no longer do is
/// stand in for parity it has no room for. Telling a movie chunk from
/// recovery data needs the bytes, and the bytes are exactly what this
/// decision runs before.
#[test]
fn a_lying_name_can_no_longer_cover_a_target_its_bytes_have_no_room_for() {
    let set = pset(2_000);
    let out = std::env::temp_dir().join("nzbfast-volcount-no-such-dir");
    let n = nzb_sized(&[
        ("rel.vol000+10.par2", raw_slice_bytes(10, 2_000)),
        ("rel.vol010+10.par2", raw_slice_bytes(10, 2_000)),
        // 41,000 bytes has room for 20 slices at this block size; the
        // name says nine hundred thousand.
        ("rel.vol9000+900000.par2", 41_000),
    ]);
    let vols = recovery_candidates(&n, &out, &set, &[], &[]);
    assert_eq!(
        vols.iter().map(|v| v.1).collect::<Vec<_>>(),
        vec![10, 10, 20],
        "the candidate loop credited a name over the bytes behind it"
    );
    // 40 blocks is past everything the impostor's bytes could hold, so
    // no selection that leaves the honest volumes out can reach it.
    let chosen = pick_volumes(&vols, 40);
    let blocks: usize = chosen.iter().fold(0usize, |a, &i| a + vols[i].1);
    assert!(
        blocks >= 40,
        "the buy came up short of the 40 blocks asked for: {chosen:?} from {vols:?}"
    );
    assert!(
        chosen.contains(&0) && chosen.contains(&1),
        "the honest parity was left unbought - one 41,000-byte file stood \
         in for 40 blocks it has no room for: {chosen:?} from {vols:?}"
    );
}
