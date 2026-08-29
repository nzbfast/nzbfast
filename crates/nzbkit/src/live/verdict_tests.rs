//! The matcher's THIRD state: [`super::LiveVerifier::slot_undecided`].
//!
//! A sibling file rather than a block in `live/tests.rs` for the reason
//! that file's own header gives - live.rs and its test module both grew
//! past comfort on TODO 311's multi-set work, and one subject per file
//! is how this tree splits them. Reached by `#[path]` from live.rs, so
//! `use super::*` still names the verifier's own module.
//!
//! What is being pinned is that "claimed nothing" is not one state but
//! two, and that they mean opposite things to settle's
//! obfuscated-alias reconciliation: a slot the matcher JUDGED and
//! refused, against a slot it never got to judge at all.

use super::*;
use md5::{Digest, Md5};

const BS: usize = 4096;
const TYPE_MAIN: &[u8; 16] = b"PAR 2.0\0Main\0\0\0\0";
const TYPE_FILEDESC: &[u8; 16] = b"PAR 2.0\0FileDesc";

fn pseudo(len: usize, seed: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(len);
    let mut x = seed | 1;
    for _ in 0..len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        v.push((x & 0xff) as u8);
    }
    v
}

fn pkt(set_id: [u8; 16], ptype: &[u8; 16], body: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(crate::par2::MAGIC);
    p.extend_from_slice(&(64 + body.len() as u64).to_le_bytes());
    p.extend_from_slice(&[0u8; 16]);
    p.extend_from_slice(&set_id);
    p.extend_from_slice(ptype);
    p.extend_from_slice(body);
    let md5: [u8; 16] = Md5::digest(&p[32..]).into();
    p[16..32].copy_from_slice(&md5);
    p
}

/// Main + one FileDesc. No IFSC: nothing here verifies a block, and a
/// set with no block grid still claims by name and by md5-16k, which is
/// the whole population of these tests.
fn index(name: &str, data: &[u8]) -> Vec<u8> {
    let fid = [7u8; 16];
    let mut main = Vec::new();
    main.extend_from_slice(&(BS as u64).to_le_bytes());
    main.extend_from_slice(&1u32.to_le_bytes());
    main.extend_from_slice(&fid);
    let mut out = pkt([1u8; 16], TYPE_MAIN, &main);
    let mut desc = Vec::new();
    desc.extend_from_slice(&fid);
    desc.extend_from_slice(&<[u8; 16]>::from(Md5::digest(data)));
    desc.extend_from_slice(&<[u8; 16]>::from(Md5::digest(
        &data[..data.len().min(16384)],
    )));
    desc.extend_from_slice(&(data.len() as u64).to_le_bytes());
    // Zero-padded to a 4-byte boundary, spelled with
    // `next_multiple_of` rather than a `% 4 != 0` push loop - clippy's
    // `manual_is_multiple_of` refuses that shape here.
    let mut nb = name.as_bytes().to_vec();
    nb.resize(nb.len().next_multiple_of(4), 0);
    desc.extend_from_slice(&nb);
    out.extend(pkt([1u8; 16], TYPE_FILEDESC, &desc));
    out
}

/// A verifier with one active one-file set over `data` named
/// `movie.mkv`, and four slots to drive independently.
fn rig(data: &[u8]) -> LiveVerifier {
    let v = LiveVerifier::with_partials_cap(4, 1 << 20);
    let idx = index("movie.mkv", data);
    v.activate(&[idx.as_slice()]).expect("index parses");
    v
}

/// A slot that CLAIMED is not undecided: the matcher has an opinion and
/// it is yes.
#[test]
fn a_claimed_slot_is_not_undecided() {
    let data = pseudo(8 * BS, 11);
    let v = rig(&data);
    v.on_data(0, "movie.mkv", data.len() as u64, 0, &data[..BS]);
    assert!(v.slot_in_set(0), "the name tier should have claimed");
    assert!(
        !v.slot_undecided(0),
        "a claim is a verdict, so the slot is decided"
    );
}

/// A slot the matcher REFUSED is not undecided either, and this is the
/// case the alias band's original reasoning was written for: the head
/// completed, so both tiers ran, and neither the name nor the md5-16k
/// digest matched anything. `unmatchable` latches and stays latched.
#[test]
fn a_slot_with_a_complete_head_that_matched_nothing_is_decided() {
    let data = pseudo(8 * BS, 11);
    let other = pseudo(8 * BS, 12);
    let v = rig(&data);
    // Offset 0 and more than HEAD_LEN, so the head completes on this one
    // article and the md5-16k tier gets its verdict.
    v.on_data(0, "somethingelse.bin", other.len() as u64, 0, &other);
    assert!(!v.slot_in_set(0), "it must not have claimed");
    assert!(
        !v.slot_undecided(0),
        "the head completed and matched nothing, so the matcher HAS decided"
    );
}

/// THE REACHABLE CASE settle's alias band used to refuse while giving a
/// false reason. Losing any article covering the first 16 KiB leaves the
/// head incomplete, so the md5-16k tier never runs, `unmatchable` is
/// never latched, and the slot claims nothing having never been judged -
/// even though it wrote plenty of bytes.
///
/// The old rule read "it wrote bytes, so it had a yEnc name to claim
/// with and did not". It had a name; what it never had was a verdict.
#[test]
fn a_slot_whose_head_never_completed_is_undecided_though_it_wrote_bytes() {
    let data = pseudo(8 * BS, 11);
    let v = rig(&data);
    // A later article only - the head article is the one that 430'd.
    v.on_data(
        0,
        "Zz9kQr4tXm7pLw2",
        data.len() as u64,
        4 * BS as u64,
        &data[4 * BS..],
    );
    assert!(!v.slot_in_set(0), "an obfuscated name claims nothing");
    assert!(
        v.slot_undecided(0),
        "the head never completed, so nothing could have decided this slot"
    );
}

/// A slot no article ever reached is undecided too - it is the same
/// third state, and the alias band's other admitted shape. Pinned so
/// the two arms of that band cannot come apart.
#[test]
fn a_slot_that_saw_no_article_at_all_is_undecided() {
    let data = pseudo(8 * BS, 11);
    let v = rig(&data);
    assert!(v.slot_undecided(3));
}

/// With no set active there is no matcher, so there is no verdict to be
/// missing and this must answer FALSE - never "undecided". A caller that
/// read true here would let the alias band admit every slot of a post
/// that has no recovery set at all.
#[test]
fn with_no_set_active_nothing_is_undecided() {
    let v = LiveVerifier::with_partials_cap(2, 1 << 20);
    assert!(!v.slot_undecided(0), "Waiting is not a verdict state");
    v.set_off();
    assert!(!v.slot_undecided(0), "Off is not a verdict state either");
}
