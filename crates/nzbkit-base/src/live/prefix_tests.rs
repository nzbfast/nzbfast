//! What the self-prove prefix hasher (`live/prefix.rs`) promises the
//! mapped repair, asserted end to end through the verifier.
//!
//! Its own file for the reason `live/blockcheck.rs` is: one subject per
//! file, and live/tests.rs was already at the size the 311 split cut it
//! down from.

use super::*;
use md5::{Digest, Md5};

fn data_of(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// A verifier with one slot, one 4-block file, and a reader over
/// `data` - the production wiring, minus the extractor.
fn rig(data: &[u8], bs: usize) -> (Arc<LiveVerifier>, Vec<u8>) {
    let v = Arc::new(LiveVerifier::new(1));
    let meta = super::tests::par2_meta([9u8; 16], bs, &[("a.bin", data)], true);
    v.activate(&[meta.as_slice()]).expect("fixture parses");
    let src = data.to_vec();
    let disk = src.clone();
    v.set_prefix_reader(Arc::new(move |_slot, off: u64, buf: &mut [u8]| {
        let off = off as usize;
        if off + buf.len() > src.len() {
            return Err(std::io::Error::other("past end"));
        }
        buf.copy_from_slice(&src[off..off + buf.len()]);
        Ok(())
    }));
    (v, disk)
}

/// Poll until `f` holds, or give up. The hasher is a background thread
/// on a 50 ms park, so every assertion about it is a wait, never a
/// sleep-and-hope.
fn until(mut f: impl FnMut() -> bool) -> bool {
    let t0 = std::time::Instant::now();
    while t0.elapsed() < std::time::Duration::from_secs(10) {
        if f() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    false
}

/// The digest a clean job carries: none. Nothing arms, so no thread is
/// spawned, nothing is read and the report is exactly what it was
/// before this existed.
#[test]
fn a_clean_slot_is_never_armed_and_reports_no_prefix() {
    let data = data_of(4096, 3);
    let (v, _) = rig(&data, 1024);
    v.on_data(0, "a.bin", 4096, 0, &data);
    let r = v.finish_slot(0, None).expect("matched");
    assert!(r.all_ok(), "the fixture is clean");
    assert!(
        r.prefix_md5.is_none(),
        "a clean download must not pay for a prefix digest"
    );
}

/// Damage that ARRIVED arms the slot, and the digest that comes back is
/// the whole-file MD5 of exactly the proven prefix - the state the
/// mapped self-prove resumes from.
#[test]
fn in_stream_damage_arms_the_hasher_and_the_digest_is_the_proven_prefix() {
    let bs = 1024;
    let data = data_of(4096, 7);
    let (v, _) = rig(&data, bs);
    // Blocks 0 and 1 land clean; block 2 arrives corrupted; block 3
    // never comes. The proven prefix is therefore blocks 0..2.
    v.on_data(0, "a.bin", 4096, 0, &data[..2 * bs]);
    let mut bad = data[2 * bs..3 * bs].to_vec();
    bad[0] ^= 0xFF;
    v.on_data(0, "a.bin", 4096, 2 * bs as u64, &bad);

    assert!(
        until(|| v.prefix_offset_for_test(0) == 2 * bs as u64),
        "the hasher should have reached the first hole, got {}",
        v.prefix_offset_for_test(0)
    );
    let r = v.finish_slot(0, None).expect("matched");
    let got = r.prefix_md5.expect("damage armed the hasher");
    assert_eq!(got.offset_for_test(), 2 * bs as u64);
    let mut want = Md5::new();
    want.update(&data[..2 * bs]);
    assert_eq!(
        got.finish_for_test(),
        <[u8; 16]>::from(want.finalize()),
        "the digest must be the FileDesc MD5 of the prefix, nothing else"
    );
}

/// A forced read-back says a range was written TWICE, so only disk can
/// say what is under it now - and the digest, which hashed the first
/// copy, goes with the verdicts it was taken beside.
#[test]
fn a_forced_readback_voids_the_digest() {
    let bs = 1024;
    let data = data_of(4096, 11);
    let (v, _) = rig(&data, bs);
    v.on_data(0, "a.bin", 4096, 0, &data[..2 * bs]);
    let mut bad = data[2 * bs..3 * bs].to_vec();
    bad[0] ^= 0xFF;
    v.on_data(0, "a.bin", 4096, 2 * bs as u64, &bad);
    assert!(until(|| v.prefix_offset_for_test(0) > 0), "hasher ran");

    v.force_readback(0);
    assert_eq!(
        v.prefix_offset_for_test(0),
        0,
        "an overlapping write must void the digest, not shorten it"
    );
    // And it does not creep back on the strength of the old frontier:
    // the reset put every block back to Pending, so there is nothing
    // proven to hash until the read-back re-earns it.
    std::thread::sleep(std::time::Duration::from_millis(120));
    assert_eq!(v.prefix_offset_for_test(0), 0);
}

/// The kill switch's rule. Asserted on the VALUE, never by setting the
/// variable: see `prefix::enabled_for` for why a row that mutates the
/// environment here breaks its siblings.
#[test]
fn the_env_switch_reads_off_and_zero_as_off() {
    for v in ["0", "off", "false"] {
        assert!(!super::prefix::enabled_for(Some(v)), "{v} must disable");
    }
    for v in [None, Some("1"), Some("on"), Some("")] {
        assert!(super::prefix::enabled_for(v), "{v:?} must leave it on");
    }
}
