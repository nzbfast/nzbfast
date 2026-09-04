//! Row M4-65's residue, closed 31 Aug 2026: the sniff that NOMINATES a
//! recovery volume and the shape test that authorises DELETING it must
//! draw the same window, or a prefixed volume is used and never swept.
//!
//! A child of `unit_tests` rather than more lines in it - that file is
//! 37 lines off the 3,000-line ceiling with several lanes appending.
//! `use super::*` reaches the parent's fixtures (`par2_volume`,
//! `payload`, `tmpdir`, `SET`, `BS`) exactly as an inline test did, and
//! the module is named for its file so size-gate.py's CFG_TEST_MOD
//! resolver keeps scoring it as test code.

use super::*;

/// The two halves of one decision, driven over one fixture set.
///
/// M4-65 widened the content sniff from "magic at byte 0" to "magic
/// beginning within [`par2::SNIFF_WINDOW`]", because an obfuscated
/// post's volumes carry a hash name and no `.par2` extension and a
/// three-byte BOM was enough to hide the whole set. M4-53's
/// [`is_recovery_volume_shape`] - the thing standing between an
/// eight-byte nomination and a `remove` - kept starting its chain at
/// offset 0. MEASURED on 31 Aug 2026 before the fix: a BOM-prefixed
/// `par2 create` volume was sniffed and answered `false` here, while
/// the byte-identical unprefixed one answered `true`.
///
/// So the sweep could not see it, and what it could not see was not an
/// untouched file: the in-stream sniff reclassifies on the same widened
/// predicate and CANCELS the volume's remaining articles, so the engine
/// holed the file itself and then abandoned it under a hash name. The
/// fix is the ENTRY POINT only - `par2::packet_file_head_offset`, the
/// function `head_is_packet_file` is defined in terms of, so neither
/// half can be narrowed without the other.
///
/// Every arm asserts BOTH answers, because either one alone is the
/// defect: a shape test that agreed where the sniff refuses would
/// delete on evidence the sniff would not spend a read on, and the
/// reverse is what shipped.
#[test]
fn the_shape_test_draws_the_same_window_as_the_sniff_that_nominated_it() {
    let d = tmpdir("volshape-prefix");
    let a = payload(200, 3);
    let vol = par2_volume(SET, BS, &[("a.bin", &a)], &[0]);
    let behind = |prefix: &[u8], tail: &[u8]| -> Vec<u8> {
        let mut v = prefix.to_vec();
        v.extend_from_slice(tail);
        v
    };
    let filler = |n: usize| vec![0xEFu8; n];
    // A deferred volume as it actually lands: the head article's
    // packets, then the hole its cancelled articles left.
    let mut deferred = pkt(SET, par2::TYPE_MAIN, &[7u8; 32]);
    deferred.extend_from_slice(&[0u8; 4096]);
    // A polyglot behind the same prefix: a valid packet, then bytes
    // somebody wants. The chain test is what must still refuse it.
    let mut poly = pkt(SET, par2::TYPE_MAIN, &[7u8; 32]);
    poly.extend_from_slice(b"\x01this is somebody's movie");
    poly.extend_from_slice(&[0u8; 4096]);

    // (name, bytes, sniffed?, volume shape?)
    let cases: &[(&str, Vec<u8>, bool, bool)] = &[
        ("plain", vol.clone(), true, true),
        // A real UTF-8 BOM: the shape M4-65 was written for.
        ("bom", behind(&[0xEF, 0xBB, 0xBF], &vol), true, true),
        // The exact window edge, both sides. This pair is the "agree by
        // construction" assertion: give volshape a constant of its own
        // and one of these two goes red.
        (
            "edge",
            behind(&filler(par2::SNIFF_WINDOW), &vol),
            true,
            true,
        ),
        (
            "past",
            behind(&filler(par2::SNIFF_WINDOW + 1), &vol),
            false,
            false,
        ),
        // A prefixed volume that was DEFERRED mid-fetch - the shape the
        // sweep meets in the field, not the chain-exact one par2 writes.
        (
            "deferred",
            behind(&[0xEF, 0xBB, 0xBF], &deferred),
            true,
            true,
        ),
        // ...and the payload that must survive the widening: prefix,
        // packet magic, then DELIVERED bytes.
        ("poly", behind(&[0xEF, 0xBB, 0xBF], &poly), true, false),
    ];
    for (name, bytes, _, _) in cases {
        std::fs::write(d.join(name), bytes).unwrap();
    }
    let sniffed = sniffed_packet_files(&d).expect("sniff walks");
    for (name, _, want_sniff, want_shape) in cases {
        let p = d.join(name);
        assert_eq!(
            sniffed.contains(&p),
            *want_sniff,
            "{name}: sniff nomination moved; got {sniffed:?}"
        );
        assert_eq!(
            is_recovery_volume_shape(&p),
            *want_shape,
            "{name}: the shape test disagrees with the window that found it"
        );
    }
    let _ = std::fs::remove_dir_all(&d);
}
