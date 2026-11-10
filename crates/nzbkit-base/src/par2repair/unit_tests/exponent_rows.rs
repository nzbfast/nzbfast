//! Parfast sweep (9 Nov 2026), Parser: recovery exponents counted on
//! the raw `u32`, so `e` and `e + 65535` - one row of the coding matrix,
//! because every RS constant is `g^e` in a group of order 65,535 - read
//! as two blocks of repair power. Verify reported a repair the set
//! cannot do; repair selected both rows and ended in `SingularMatrix`
//! instead of the shortfall verdict the set actually earns.
//! `par2::recovery_row` is the one reduction every counting and
//! selection site now keys on.
//!
//! No real producer writes an exponent at or past 65,535, so this is a
//! crafted-set shape; what it pins is that such a set gets an honest
//! verdict. A CHILD of `unit_tests` for `padded_windows`' two reasons.

use super::*;

/// Two damaged blocks, and recovery packets at exponents 0 and 65,535,
/// which are the SAME row: one block of repair power, not two.
#[test]
fn an_exponent_and_its_alias_mod_65535_count_once() {
    let dir = tmpdir("exp-alias");
    let a = payload(BS * 4, 61);
    let files: &[(&str, &[u8])] = &[("a.bin", &a)];
    let index = par2_index(SET, BS, files);
    let vol = par2_volume(SET, BS, files, &[0, 65_535]);
    std::fs::write(dir.join("set.par2"), &index).unwrap();
    std::fs::write(dir.join("set.vol0+2.par2"), &vol).unwrap();
    let mut damaged = a.clone();
    for x in &mut damaged[..BS * 2] {
        *x ^= 0x5A;
    }
    std::fs::write(dir.join("a.bin"), &damaged).unwrap();

    let set = crate::par2::Par2Set::parse(&[&index, &vol]).expect("the set parses");
    assert_eq!(
        set.recovery_blocks_seen, 1,
        "exponents 0 and 65535 are one row of the coding matrix"
    );

    match repair_dir(&dir) {
        Ok(RepairStatus::Unrepairable { needed, have, .. }) => {
            assert_eq!((needed, have), (2, 1), "one row for two damaged blocks");
        }
        other => panic!("an aliased pair must be a shortfall, not {other:?}"),
    }
    assert_eq!(
        std::fs::read(dir.join("a.bin")).unwrap(),
        damaged,
        "a shortfall writes nothing over an existing member"
    );
}

/// Parfast sweep A27: a SINGULAR selection is not terminal when the set
/// holds a spare recovery row. Slices 0 and 2 have input logs 1 and 4,
/// whose bases' ratio `2^3` has order 21,845 - so exponents 0 and 21,845
/// are a singular pair over exactly those two missing slices. With no
/// consecutive pair among {0, 21845, 30000} the ordinary selection falls
/// back to the smallest two and fails; {0, 30000} is independent and
/// repairs. It used to end in `SingularMatrix` with the spare row unused.
#[test]
fn a_singular_selection_reselects_from_spare_recovery_rows() {
    let dir = tmpdir("a27-reselect");
    let a = payload(BS * 4, 63);
    let files: &[(&str, &[u8])] = &[("a.bin", &a)];
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    std::fs::write(
        dir.join("set.vol0+3.par2"),
        par2_volume(SET, BS, files, &[0, 21_845, 30_000]),
    )
    .unwrap();
    let mut damaged = a.clone();
    for blk in [0usize, 2] {
        for x in &mut damaged[blk * BS..(blk + 1) * BS] {
            *x ^= 0x3C;
        }
    }
    std::fs::write(dir.join("a.bin"), &damaged).unwrap();
    match repair_dir(&dir) {
        Ok(RepairStatus::Repaired(r)) => assert_eq!(r.blocks_rebuilt, 2, "{r:?}"),
        other => panic!("a spare independent row must repair this set: {other:?}"),
    }
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a);
}

/// A27's other half: with NO spare row the singular pair is still a
/// `SingularMatrix`, and the reselect does not loop.
#[test]
fn a_singular_selection_with_no_spare_row_stays_singular() {
    let dir = tmpdir("a27-no-spare");
    let a = payload(BS * 4, 64);
    let files: &[(&str, &[u8])] = &[("a.bin", &a)];
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    std::fs::write(
        dir.join("set.vol0+2.par2"),
        par2_volume(SET, BS, files, &[0, 21_845]),
    )
    .unwrap();
    let mut damaged = a.clone();
    for blk in [0usize, 2] {
        damaged[blk * BS] ^= 0x3C;
    }
    std::fs::write(dir.join("a.bin"), &damaged).unwrap();
    assert!(
        matches!(repair_dir(&dir), Err(RepairError::SingularMatrix)),
        "two dependent rows for two missing blocks is genuinely singular"
    );
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), damaged);
}

/// A27 follow-up: the reselect's `m x m` basis is priced against the
/// solve-window budget. One that does not fit is refused (`None`, so the
/// caller keeps its `SingularMatrix`) rather than allocated past the
/// budget. m = 2 here, so the basis is 8 bytes: 8 fits, 7 does not.
#[test]
fn the_reselect_basis_is_refused_past_the_solve_budget() {
    use crate::par2repair::reconstruct::ForcedSolveBudget;
    let by_exp: HashMap<u32, ()> = [(0u32, ()), (21_845, ()), (30_000, ())].into();
    let missing = [0usize, 2];
    let control = crate::par2repair::control::RepairControl::default();
    {
        let _b = ForcedSolveBudget::set(8);
        assert_eq!(
            crate::par2repair::catalog::independent_rows(4, &missing, &by_exp, &control)
                .expect("no error"),
            Some(vec![0, 30_000]),
            "a basis that fits is built, and skips the dependent row"
        );
    }
    let _b = ForcedSolveBudget::set(7);
    assert_eq!(
        crate::par2repair::catalog::independent_rows(4, &missing, &by_exp, &control)
            .expect("no error"),
        None,
        "a basis past the budget is no reselect"
    );
}
