//! Wave-4 row M4-53's shape test, and the interior hole that row's
//! first cut could not see (31 Aug 2026).
//!
//! A child of `unit_tests` rather than a sibling, for its fixture
//! helpers - `pkt`, `payload`, `tmpdir`, `SET` - and because
//! `unit_tests.rs` was at 2,963 of the 3,000-line ceiling when the
//! interior-hole arms landed.

use super::*;

/// Wave-4 row M4-53: the shape test that stands between an eight-byte
/// nomination and a delete.
///
/// Every arm here is a file the sweep's callers would otherwise have
/// judged identically, because all of them open with the packet magic
/// and none of them is named `.par2`. Driven at this level and not
/// through an e2e because the two failure directions are opposite in
/// cost: a payload wrongly swept is bytes gone, a volume wrongly kept
/// is issue #9 back again, and only one of them has a fixture.
#[test]
fn only_packets_and_holes_read_as_a_recovery_volume() {
    let d = tmpdir("volshape");
    let one = pkt(SET, par2::TYPE_MAIN, &[7u8; 32]);
    // A whole volume: packets, chain landing exactly on EOF.
    let mut whole = one.clone();
    whole.extend_from_slice(&pkt(SET, par2::TYPE_FILEDESC, &[3u8; 48]));
    std::fs::write(d.join("whole"), &whole).unwrap();
    assert!(is_recovery_volume_shape(&d.join("whole")));
    // The DEFERRED volume the sniff actually leaves on disk: the head
    // article's packets, then the hole its cancelled articles left.
    // An EOF-exact rule keeps this one forever, which is the whole
    // reason the hole is part of the shape.
    let mut partial = one.clone();
    partial.extend_from_slice(&[0u8; 4096]);
    std::fs::write(d.join("partial"), &partial).unwrap();
    assert!(is_recovery_volume_shape(&d.join("partial")));
    // The polyglot: a VALID first packet, then payload. One non-zero
    // byte past the chain is the whole difference, so the test puts it
    // at the very first byte a volume would have left a hole in.
    let mut poly = one.clone();
    poly.extend_from_slice(b"\x01this is somebody's movie");
    poly.extend_from_slice(&[0u8; 4096]);
    std::fs::write(d.join("poly"), &poly).unwrap();
    assert!(!is_recovery_volume_shape(&d.join("poly")));
    // Magic and nothing else behind it: never a packet at all.
    let mut bare = par2::MAGIC.to_vec();
    bare.extend_from_slice(&payload(4096, 11));
    std::fs::write(d.join("bare"), &bare).unwrap();
    assert!(!is_recovery_volume_shape(&d.join("bare")));
    // A file with no magic is not this shape either, and neither is a
    // file that is not there.
    std::fs::write(d.join("plain"), payload(4096, 12)).unwrap();
    assert!(!is_recovery_volume_shape(&d.join("plain")));
    assert!(!is_recovery_volume_shape(&d.join("absent")));

    // THE INTERIOR HOLE (31 Aug 2026). A deferral cancels a sniffed
    // slot's still-QUEUED articles and the ones already IN FLIGHT
    // land, so what is on disk is routinely NOT a prefix: an article
    // past the cancelled ones arrived, and the file is packets, hole,
    // packets, hole. A trailing-hole-only rule reads this as payload
    // and keeps it, which is the flake this arm pins - the real
    // leftover was 134 packets, a 201,680-byte hole, a straddling
    // packet's tail, more packets, then a trailing hole.
    let big = pkt(SET, par2::TYPE_FILEDESC, &[5u8; 4096]);
    let mut interior = big.clone();
    interior.extend_from_slice(&[0u8; 8192]); // the hole
    interior.extend_from_slice(&payload(512, 21)); // a straddling tail
    interior.extend_from_slice(&one); // the chain picks up again
    interior.extend_from_slice(&[0u8; 2048]); // and a trailing hole
    std::fs::write(d.join("interior"), &interior).unwrap();
    assert!(is_recovery_volume_shape(&d.join("interior")));
    // Two holes, and the last packet landing exactly on EOF.
    let mut twohole = big.clone();
    twohole.extend_from_slice(&[0u8; 1024]);
    twohole.extend_from_slice(&one);
    twohole.extend_from_slice(&[0u8; 1024]);
    twohole.extend_from_slice(&one);
    std::fs::write(d.join("twohole"), &twohole).unwrap();
    assert!(is_recovery_volume_shape(&d.join("twohole")));
    // The unaccounted span is bounded by the longest packet the FILE
    // has declared and this walk has stepped over. Past that bound
    // there is no straddling packet that could explain the bytes, so
    // they are somebody's payload and the file is KEPT.
    let mut overrun = one.clone();
    overrun.extend_from_slice(&[0u8; 1024]);
    overrun.extend_from_slice(&payload(one.len() + 64, 22));
    overrun.extend_from_slice(&one);
    overrun.extend_from_slice(&[0u8; 1024]);
    std::fs::write(d.join("overrun"), &overrun).unwrap();
    assert!(!is_recovery_volume_shape(&d.join("overrun")));
    // A hole with delivered bytes past it and no chain to pick up is
    // payload too: the resume is what accounts for the bytes, and
    // there is none.
    let mut nochain = big.clone();
    nochain.extend_from_slice(&[0u8; 1024]);
    nochain.extend_from_slice(&payload(512, 23));
    std::fs::write(d.join("nochain"), &nochain).unwrap();
    assert!(!is_recovery_volume_shape(&d.join("nochain")));
    let _ = std::fs::remove_dir_all(&d);
}
