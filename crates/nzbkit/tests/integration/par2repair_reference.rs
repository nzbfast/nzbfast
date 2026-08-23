//! RS reconstruction validated against REAL par2cmdline 1.2.0 recovery
//! data (tests/fixtures/par2/README.txt). This is the test that pins our
//! GF(2^16) constants, exponent handling, and slice ordering to the
//! reference implementation: the recovery slices in testset.vol0+4.par2
//! were computed by par2cmdline, so reconstruction only succeeds if our
//! math matches it bit-for-bit.

use nzbkit::par2::Par2Set;
use nzbkit::par2repair::{Reconstructor, recovery_slice_locators};

const MAIN: &[u8] = include_bytes!("../fixtures/par2/testset.par2");
const VOL: &[u8] = include_bytes!("../fixtures/par2/testset.vol0+4.par2");
const ALPHA: &[u8] = include_bytes!("../fixtures/par2/alpha.bin"); // 10 KiB
const BETA: &[u8] = include_bytes!("../fixtures/par2/beta.bin"); // 33 KiB

/// The fixture set: block 4096, Main order [beta (9 slices), alpha (3)].
/// Returns (block_size, per-file (data, first_slice, n_slices) in Main
/// order, the 4 recovery slices from the volume).
fn fixture() -> (
    usize,
    Vec<(&'static [u8], usize, usize)>,
    Vec<(u32, Vec<u8>)>,
) {
    let set = Par2Set::parse(&[MAIN, VOL]).expect("fixture parses");
    let bs = set.block_size as usize;
    assert_eq!(set.files[0].name, "beta.bin");
    assert_eq!(set.files[1].name, "alpha.bin");
    let mut layout = Vec::new();
    let mut next = 0usize;
    for (f, data) in set.files.iter().zip([BETA, ALPHA]) {
        let n = f.length.div_ceil(set.block_size) as usize;
        layout.push((data, next, n));
        next += n;
    }
    let recovery: Vec<(u32, Vec<u8>)> = recovery_slice_locators(VOL, &set.recovery_set_id)
        .into_iter()
        .map(|(e, off, len)| {
            assert_eq!(len, bs, "recovery slice data is one block");
            (e, VOL[off..off + len].to_vec())
        })
        .collect();
    assert_eq!(recovery.len(), 4, "vol0+4 carries 4 recovery slices");
    (bs, layout, recovery)
}

/// The i-th slice of `data`, zero-padded to the block size.
fn slice_of(data: &[u8], i: usize, bs: usize) -> Vec<u8> {
    let start = i * bs;
    let end = (start + bs).min(data.len());
    let mut v = data[start..end].to_vec();
    v.resize(bs, 0);
    v
}

fn reconstruct_and_check(missing: &[usize]) {
    let (bs, layout, mut recovery) = fixture();
    let n_inputs: usize = layout.iter().map(|&(_, _, n)| n).sum();
    recovery.truncate(missing.len());
    let mut rec = Reconstructor::new(bs, n_inputs, missing, &recovery).expect("matrix inverts");
    for &(data, first, n) in &layout {
        for i in 0..n {
            let g = first + i;
            if !missing.contains(&g) {
                let start = i * bs;
                let end = (start + bs).min(data.len());
                rec.feed(g, &data[start..end]);
            }
        }
    }
    let rebuilt = rec.finish();
    for (out, &g) in rebuilt.iter().zip(missing) {
        let &(data, first, _) = layout
            .iter()
            .find(|&&(_, first, n)| g >= first && g < first + n)
            .unwrap();
        assert_eq!(
            out,
            &slice_of(data, g - first, bs),
            "slice {g} byte-identical to the original"
        );
    }
}

#[test]
fn one_missing_slice_reconstructs_from_reference_recovery_data() {
    reconstruct_and_check(&[0]); // beta block 0
}

#[test]
fn tail_slices_reconstruct_with_correct_padding() {
    // beta's tail (33792 = 8·4096 + 1024) and alpha's tail (10240 =
    // 2·4096 + 2048) - both zero-padded in the RS math.
    reconstruct_and_check(&[8, 11]);
}

#[test]
fn max_damage_uses_all_four_reference_slices() {
    // Scattered across both files, including both file heads.
    reconstruct_and_check(&[0, 5, 9, 10]);
}

#[test]
fn locators_report_the_reference_exponents() {
    let set = Par2Set::parse(&[MAIN, VOL]).expect("fixture parses");
    let mut exps: Vec<u32> = recovery_slice_locators(VOL, &set.recovery_set_id)
        .into_iter()
        .map(|(e, _, _)| e)
        .collect();
    exps.sort_unstable();
    assert_eq!(
        exps,
        vec![0, 1, 2, 3],
        "par2cmdline numbers exponents from 0"
    );
}
