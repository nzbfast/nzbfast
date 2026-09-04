//! Differential and known-answer tests for [`super::Md5`].
//!
//! On Windows x86-64 `super::Md5` is this crate's inline-assembly
//! implementation and `md5::Md5` is the `md-5` crate's portable one, so
//! every assertion below is a real differential. On every other target
//! the two are the same type and the file degrades to a fast
//! self-consistency check - deliberately, because the day somebody
//! widens the `cfg` the harness is already in place and already wired
//! into the suite. The RFC 1321 vectors at the bottom are absolute
//! either way.

use super::{Digest, Md5};

/// xorshift64*, so the corpus is deterministic without a dev-dependency.
fn fill(seed: u64, out: &mut [u8]) {
    let mut s = seed | 1;
    for b in out.iter_mut() {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        *b = (s >> 33) as u8;
    }
}

fn reference(data: &[u8]) -> [u8; 16] {
    <md5::Md5 as md5::Digest>::digest(data).into()
}

fn ours(data: &[u8]) -> [u8; 16] {
    let d: [u8; 16] = Md5::digest(data).into();
    d
}

/// Every length that can land on a padding edge, plus a spread of
/// ordinary ones and one multi-megabyte input.
///
/// The interesting cases are 55 (padding fits in the final block), 56
/// (it does not, so finalisation compresses one extra block), 63/64/65
/// (block boundary) and 119/120 (the same edge one block up). 0 is the
/// empty message, which is the one input where the block function is
/// never called on user bytes at all.
#[test]
fn md5_differential_by_length() {
    let mut lens: Vec<usize> = (0..=200).collect();
    lens.extend([
        255,
        256,
        511,
        512,
        1000,
        4096,
        65_536,
        1 << 20,
        (3 << 20) + 7,
    ]);
    let mut buf = vec![0u8; (3 << 20) + 7];
    fill(0x9E37_79B9_7F4A_7C15, &mut buf);
    for n in lens {
        let data = &buf[..n];
        assert_eq!(
            ours(data),
            reference(data),
            "one-shot digest differs at len {n}"
        );
    }
}

/// The same corpus fed through `update` in uneven pieces, so the block
/// buffer holds a partial block across calls the way a real read loop
/// leaves it.
#[test]
fn md5_differential_chunked_updates() {
    let mut buf = vec![0u8; 300_000];
    fill(0xD1B5_4A32_D192_ED03, &mut buf);
    for chunk in [1usize, 2, 3, 7, 31, 63, 64, 65, 127, 1000, 4096, 65_536] {
        let mut h = Md5::new();
        let mut r = <md5::Md5 as md5::Digest>::new();
        for piece in buf.chunks(chunk) {
            h.update(piece);
            md5::Digest::update(&mut r, piece);
        }
        let got: [u8; 16] = h.finalize().into();
        let want: [u8; 16] = r.finalize().into();
        assert_eq!(got, want, "chunked digest differs at chunk size {chunk}");
        assert_eq!(got, reference(&buf), "chunked digest differs from one-shot");
    }
}

/// Clone-and-resume at every 64-byte block boundary of a multi-block
/// message.
///
/// This is the shape [`crate::par2repair::Md5Resume`] is built on: the
/// verify pass clones a live hasher at a block start, and a later
/// self-prove finishes that clone over the bytes it rewrote instead of
/// rereading the file from zero. The clone must therefore be an exact
/// copy of the chaining state AND of the partial-block buffer, and the
/// original must be unaffected by it - both asserted here.
#[test]
fn md5_clone_resume_at_every_block_boundary() {
    let mut buf = vec![0u8; 64 * 40 + 37];
    fill(0x2545_F491_4F6C_DD1D, &mut buf);
    let want = reference(&buf);
    for cut in 0..=buf.len() {
        let (head, tail) = buf.split_at(cut);
        let mut h = Md5::new();
        h.update(head);
        let mut resumed = h.clone();
        resumed.update(tail);
        let got: [u8; 16] = resumed.finalize().into();
        assert_eq!(got, want, "resume from a clone differs at cut {cut}");
        // The clone must not have disturbed the original.
        h.update(tail);
        let again: [u8; 16] = h.finalize().into();
        assert_eq!(
            again, want,
            "the cloned-from hasher was disturbed at cut {cut}"
        );
    }
}

/// A length well past 2^32 bits is not testable here, but the bit-length
/// counter's low end is: the block counter is bumped per block and the
/// tail bytes separately, so a message whose length straddles both must
/// still agree.
#[test]
fn md5_differential_random_lengths() {
    let mut buf = vec![0u8; 300_000];
    fill(0x8A5C_D789_635D_2DFF, &mut buf);
    let mut s: u64 = 12_345;
    for _ in 0..500 {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        let n = (s % (buf.len() as u64 + 1)) as usize;
        let data = &buf[..n];
        assert_eq!(
            ours(data),
            reference(data),
            "random-length digest differs at len {n}"
        );
    }
}

/// RFC 1321 appendix A.5, verbatim. Nothing in this file's differential
/// arms would notice if BOTH sides were wrong the same way; these would.
#[test]
fn md5_rfc1321_vectors() {
    let cases: [(&str, &str); 7] = [
        ("", "d41d8cd98f00b204e9800998ecf8427e"),
        ("a", "0cc175b9c0f1b6a831c399e269772661"),
        ("abc", "900150983cd24fb0d6963f7d28e17f72"),
        ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
        (
            "abcdefghijklmnopqrstuvwxyz",
            "c3fcd3d76192e4007dfb496cca67e13b",
        ),
        (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "d174ab98d277d9f5a5611c2c9f419d9f",
        ),
        (
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "57edf4a22be3c955ac49da2e2107b67a",
        ),
    ];
    for (input, want) in cases {
        let got = ours(input.as_bytes());
        let hex: String = got.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, want, "RFC 1321 vector failed for {input:?}");
    }
}
