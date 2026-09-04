//! Encrypted-zip primitives (zip phase 3): the legacy PKWARE
//! "ZipCrypto" stream cipher and the WinZip AE scheme (PBKDF2-HMAC-SHA1
//! key derivation, AES-CTR with a little-endian counter, HMAC-SHA1
//! authentication). Decrypt side only - nzbfast reads posted archives,
//! it does not write encrypted ones outside test fixtures.
//!
//! Everything here rides dependencies the tree already carries (`aes`,
//! `hmac`, `sha1`), the same zero-new-deps rule the deflate decision
//! followed. PBKDF2 is hand-rolled like rarcrypt's RAR5 chain and
//! pinned to the RFC 6070 vectors below.
//!
//! Security posture, stated plainly: ZipCrypto is a BROKEN cipher
//! (known-plaintext attacks recover its 96-bit state) and is
//! implemented because posted archives use it, not because it protects
//! anything. AE's HMAC is the real integrity check; AE-2 deliberately
//! zeroes the CRC field, so the caller must skip the CRC comparison
//! for it (see `AesSpec::skips_crc`).

use aes::cipher::array::Array;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use hmac::digest::KeyInit as MacKeyInit;
use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

// ---------------------------------------------------------------------------
// ZipCrypto (PKWARE traditional encryption)
// ---------------------------------------------------------------------------

/// Standard CRC-32 (reflected, poly 0xEDB88320) over one byte - the
/// primitive ZipCrypto's key schedule is built from. Bytewise on
/// purpose: the cipher consumes it one byte at a time, and a table buys
/// nothing at that grain.
fn crc32_byte(crc: u32, b: u8) -> u32 {
    let mut c = crc ^ b as u32;
    for _ in 0..8 {
        c = if c & 1 != 0 {
            (c >> 1) ^ 0xEDB8_8320
        } else {
            c >> 1
        };
    }
    c
}

/// The ZipCrypto keystream state: three rotating 32-bit keys seeded
/// from the password, advanced by every PLAINTEXT byte.
pub struct ZipCrypto {
    k: [u32; 3],
}

impl ZipCrypto {
    pub fn new(password: &[u8]) -> ZipCrypto {
        let mut z = ZipCrypto {
            k: [0x1234_5678, 0x2345_6789, 0x3456_7890],
        };
        for &b in password {
            z.update(b);
        }
        z
    }

    fn update(&mut self, plain: u8) {
        self.k[0] = crc32_byte(self.k[0], plain);
        self.k[1] = self.k[1]
            .wrapping_add(self.k[0] & 0xFF)
            .wrapping_mul(134_775_813)
            .wrapping_add(1);
        self.k[2] = crc32_byte(self.k[2], (self.k[1] >> 24) as u8);
    }

    fn keystream_byte(&self) -> u8 {
        let t = (self.k[2] | 2) as u16;
        (t.wrapping_mul(t ^ 1) >> 8) as u8
    }

    /// Decrypt in place.
    pub fn decrypt(&mut self, data: &mut [u8]) {
        for b in data {
            let p = *b ^ self.keystream_byte();
            self.update(p);
            *b = p;
        }
    }

    /// Encrypt in place (fixture writer only - the cipher is symmetric
    /// but the key schedule follows PLAINTEXT, so the two directions
    /// differ in which byte feeds `update`).
    pub fn encrypt(&mut self, data: &mut [u8]) {
        for b in data {
            let c = *b ^ self.keystream_byte();
            self.update(*b);
            *b = c;
        }
    }
}

/// The 12-byte ZipCrypto header's check byte for an entry: the high
/// byte of the CRC normally, but the high byte of the DOS mod TIME when
/// general-purpose bit 3 is set (the CRC was not known yet when the
/// local header was written). One byte, so a wrong password still
/// passes 1 time in 256 - the post-decrypt CRC32 is what actually
/// vouches for the bytes.
pub fn zipcrypto_check_byte(flags: u16, crc32: u32, dos_time: u16) -> u8 {
    if flags & 0x0008 != 0 {
        (dos_time >> 8) as u8
    } else {
        (crc32 >> 24) as u8
    }
}

// ---------------------------------------------------------------------------
// WinZip AE (AES)
// ---------------------------------------------------------------------------

/// PBKDF2-HMAC-SHA1 (RFC 2898), the WinZip AE key derivation. Written
/// out like rarcrypt's RAR5 chain rather than pulling a crate for a
/// 20-line loop; pinned to the RFC 6070 vectors in the tests.
pub fn pbkdf2_sha1(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    for (block, chunk) in (1_u32..).zip(out.chunks_mut(20)) {
        let mut mac = <HmacSha1 as MacKeyInit>::new_from_slice(password)
            .expect("hmac accepts any key length");
        mac.update(salt);
        mac.update(&block.to_be_bytes());
        let mut u = mac.finalize().into_bytes();
        let mut t = u;
        for _ in 1..iterations {
            let mut m = <HmacSha1 as MacKeyInit>::new_from_slice(password)
                .expect("hmac accepts any key length");
            m.update(&u);
            u = m.finalize().into_bytes();
            for (a, b) in t.iter_mut().zip(u.iter()) {
                *a ^= b;
            }
        }
        chunk.copy_from_slice(&t[..chunk.len()]);
    }
}

/// AES key strength from the AE extra field's strength byte.
/// `(key_len, salt_len)`; salt is always half the key.
pub fn ae_strength_lens(strength: u8) -> Option<(usize, usize)> {
    match strength {
        1 => Some((16, 8)),
        2 => Some((24, 12)),
        3 => Some((32, 16)),
        _ => None,
    }
}

/// WinZip AE iteration count - fixed by the spec.
pub const AE_PBKDF2_ITERATIONS: u32 = 1000;
/// The 2-byte password verifier that follows the salt.
pub const AE_VERIFY_LEN: usize = 2;
/// The truncated HMAC-SHA1 authentication code that follows the data.
pub const AE_AUTH_LEN: usize = 10;

enum AnyAes {
    A128(aes::Aes128),
    A192(aes::Aes192),
    A256(aes::Aes256),
}

/// WinZip AE-CTR keystream: AES over a 128-bit LITTLE-ENDIAN counter
/// that starts at 1 (not the NIST big-endian convention), XORed onto
/// the data. A true stream: partial keystream blocks carry across
/// calls, because the caller's reads arrive at whatever granularity a
/// deflate decoder pulls. Symmetric, so the fixture writer uses it
/// as-is.
pub struct AeCtr {
    cipher: AnyAes,
    counter: u128,
    ks: [u8; 16],
    used: usize,
}

impl AeCtr {
    /// `key` must be 16/24/32 bytes (see [`ae_strength_lens`]).
    pub fn new(key: &[u8]) -> Option<AeCtr> {
        let cipher = match key.len() {
            16 => AnyAes::A128(aes::Aes128::new_from_slice(key).ok()?),
            24 => AnyAes::A192(aes::Aes192::new_from_slice(key).ok()?),
            32 => AnyAes::A256(aes::Aes256::new_from_slice(key).ok()?),
            _ => return None,
        };
        Some(AeCtr {
            cipher,
            counter: 1,
            ks: [0; 16],
            used: 16,
        })
    }

    fn refill(&mut self) {
        self.ks = self.counter.to_le_bytes();
        let ga = <&mut Array<u8, aes::cipher::consts::U16>>::from(&mut self.ks);
        match &self.cipher {
            AnyAes::A128(c) => c.encrypt_block(ga),
            AnyAes::A192(c) => c.encrypt_block(ga),
            AnyAes::A256(c) => c.encrypt_block(ga),
        }
        self.counter += 1;
        self.used = 0;
    }

    /// Encrypt a run of counter blocks in ONE call, which is what lets
    /// the AES implementation pipeline its rounds across blocks.
    fn encrypt_batch(&self, blocks: &mut [AeBlock]) {
        match &self.cipher {
            AnyAes::A128(c) => c.encrypt_blocks(blocks),
            AnyAes::A192(c) => c.encrypt_blocks(blocks),
            AnyAes::A256(c) => c.encrypt_blocks(blocks),
        }
    }

    /// XOR the next keystream bytes onto `data`, any length.
    ///
    /// Whole blocks go through `encrypt_blocks` a batch at a time; only
    /// the ragged ends touch the carried `ks`. The keystream this
    /// produces is byte-identical to the block-at-a-time original -
    /// `ae_ctr_batching_matches_the_block_at_a_time_keystream` pins that
    /// over ragged call boundaries - because the counter still advances
    /// one per block in the same order. It is worth the code: at 1 GiB
    /// the old shape was 67 million single-block `encrypt_block` calls
    /// with a branch per BYTE, and AES-256 zip is the one zip shape that
    /// was behind 7-Zip (research/RAR-PERF-AUDIT-2026-09-02.md, round 13).
    pub fn xor(&mut self, data: &mut [u8]) {
        let mut off = 0usize;
        // The partial block carried over from the previous call.
        if self.used < 16 {
            let n = (16 - self.used).min(data.len());
            for (i, d) in data[..n].iter_mut().enumerate() {
                *d ^= self.ks[self.used + i];
            }
            self.used += n;
            off = n;
        }
        // Whole blocks, in batches.
        const BATCH: usize = 8;
        let mut blocks = [AeBlock::default(); BATCH];
        while off + 16 * BATCH <= data.len() {
            for b in blocks.iter_mut() {
                *b = AeBlock::from(self.counter.to_le_bytes());
                self.counter += 1;
            }
            self.encrypt_batch(&mut blocks);
            for b in blocks.iter() {
                for (d, k) in data[off..off + 16].iter_mut().zip(b.iter()) {
                    *d ^= *k;
                }
                off += 16;
            }
        }
        // Whole blocks below one batch.
        while off + 16 <= data.len() {
            let mut b = AeBlock::from(self.counter.to_le_bytes());
            self.counter += 1;
            self.encrypt_batch(std::slice::from_mut(&mut b));
            for (d, k) in data[off..off + 16].iter_mut().zip(b.iter()) {
                *d ^= *k;
            }
            off += 16;
        }
        // The ragged tail becomes the carried block for the next call.
        if off < data.len() {
            self.refill();
            let n = data.len() - off;
            for (i, d) in data[off..].iter_mut().enumerate() {
                *d ^= self.ks[i];
            }
            self.used = n;
        }
    }
}

/// One AES block, the shape `encrypt_blocks` takes a slice of.
type AeBlock = Array<u8, aes::cipher::consts::U16>;

/// Derived AE material for one entry: the CTR key, the HMAC key, and
/// the 2-byte password verifier.
pub struct AeKeys {
    pub(crate) enc_key: Vec<u8>,
    pub(crate) mac_key: Vec<u8>,
    pub(crate) verify: [u8; AE_VERIFY_LEN],
}

pub fn ae_derive(password: &[u8], salt: &[u8], key_len: usize) -> AeKeys {
    let mut dk = vec![0u8; key_len * 2 + AE_VERIFY_LEN];
    pbkdf2_sha1(password, salt, AE_PBKDF2_ITERATIONS, &mut dk);
    let verify = [dk[key_len * 2], dk[key_len * 2 + 1]];
    let mac_key = dk[key_len..key_len * 2].to_vec();
    dk.truncate(key_len);
    AeKeys {
        enc_key: dk,
        mac_key,
        verify,
    }
}

/// Incremental HMAC-SHA1 over the CIPHERTEXT (the AE authentication is
/// encrypt-then-MAC), finishing to the truncated 10-byte code.
pub struct AeMac(HmacSha1);

impl AeMac {
    pub fn new(mac_key: &[u8]) -> AeMac {
        AeMac(
            <HmacSha1 as MacKeyInit>::new_from_slice(mac_key).expect("hmac accepts any key length"),
        )
    }
    pub fn update(&mut self, ciphertext: &[u8]) {
        self.0.update(ciphertext);
    }
    pub fn finalize(self) -> [u8; AE_AUTH_LEN] {
        let full = self.0.finalize().into_bytes();
        let mut out = [0u8; AE_AUTH_LEN];
        out.copy_from_slice(&full[..AE_AUTH_LEN]);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The batched keystream must be byte-identical to the
    /// block-at-a-time one it replaced, INCLUDING across ragged call
    /// boundaries - a caller's read sizes are whatever a deflate decoder
    /// hands up, so the carried partial block is the normal case and not
    /// an edge one. Sizes below, at and above a block, either side of a
    /// full 8-block batch, and a run long enough to take several batches.
    ///
    /// The reference here is deliberately a LOCAL re-implementation of
    /// the old shape rather than a stored vector: it is the property
    /// (same counter, same order, one block at a time) that has to hold,
    /// and a vector would only pin one call pattern.
    #[test]
    fn ae_ctr_batching_matches_the_block_at_a_time_keystream() {
        /// The pre-batching `AeCtr::xor`, verbatim.
        fn reference(key: &[u8], chunks: &[usize], out: &mut [u8]) {
            let mut ctr = AeCtr::new(key).expect("key length");
            let mut off = 0usize;
            let mut i = 0usize;
            while off < out.len() {
                let n = chunks[i % chunks.len()].min(out.len() - off);
                for d in out[off..off + n].iter_mut() {
                    if ctr.used == 16 {
                        ctr.refill();
                    }
                    *d ^= ctr.ks[ctr.used];
                    ctr.used += 1;
                }
                off += n;
                i += 1;
            }
        }
        for key_len in [16usize, 24, 32] {
            let key = vec![0x5au8; key_len];
            // Deliberately ragged: 1 and 15 leave a partial block behind,
            // 16 and 128 (= 8 blocks) land exactly, 17/31/33 straddle,
            // and 12_345 crosses many batches at an unaligned offset.
            let chunks = [1usize, 15, 16, 17, 31, 128, 129, 33, 4096, 12_345];
            let mut want = vec![0u8; 200_000];
            reference(&key, &chunks, &mut want);
            let mut got = vec![0u8; want.len()];
            let mut ctr = AeCtr::new(&key).expect("key length");
            let (mut off, mut i) = (0usize, 0usize);
            while off < got.len() {
                let n = chunks[i % chunks.len()].min(got.len() - off);
                ctr.xor(&mut got[off..off + n]);
                off += n;
                i += 1;
            }
            assert_eq!(got, want, "AES-{} keystream diverged", key_len * 8);
        }
    }

    /// RFC 6070 PBKDF2-HMAC-SHA1 vectors - the derivation the whole AE
    /// scheme hangs off.
    #[test]
    fn pbkdf2_sha1_rfc6070_vectors() {
        let cases: [(&[u8], &[u8], u32, &str); 3] = [
            (
                b"password",
                b"salt",
                1,
                "0c60c80f961f0e71f3a9b524af6012062fe037a6",
            ),
            (
                b"password",
                b"salt",
                2,
                "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957",
            ),
            (
                b"password",
                b"salt",
                4096,
                "4b007901b765489abead49d926f721d065a429c1",
            ),
        ];
        for (pw, salt, c, want) in cases {
            let mut out = [0u8; 20];
            pbkdf2_sha1(pw, salt, c, &mut out);
            let got: String = out.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(got, want, "c={c}");
        }
        // Multi-block output (dkLen > 20) - the AE shape (2*key+2).
        let mut out = [0u8; 25];
        pbkdf2_sha1(
            b"passwordPASSWORDpassword",
            b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
            4096,
            &mut out,
        );
        let got: String = out.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(got, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038");
    }

    /// ZipCrypto round-trip: encrypt with the key schedule following
    /// plaintext, decrypt with it following the recovered plaintext.
    #[test]
    fn zipcrypto_round_trip() {
        let data: Vec<u8> = (0..4096u32).map(|i| (i * 31 + 7) as u8).collect();
        let mut buf = data.clone();
        ZipCrypto::new(b"s3cret").encrypt(&mut buf);
        assert_ne!(buf, data, "ciphertext must differ");
        ZipCrypto::new(b"s3cret").decrypt(&mut buf);
        assert_eq!(buf, data);
        // Wrong password does not round-trip.
        let mut bad = data.clone();
        ZipCrypto::new(b"s3cret").encrypt(&mut bad);
        ZipCrypto::new(b"wrong").decrypt(&mut bad);
        assert_ne!(bad, data);
    }

    /// AE-CTR round-trip across ARBITRARY chunk boundaries - a deflate
    /// decoder pulls whatever sizes it likes, so partial keystream
    /// blocks must carry across calls.
    #[test]
    fn ae_ctr_round_trip_and_chunking() {
        let key = [7u8; 32];
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 13 + 5) as u8).collect();
        let mut whole = data.clone();
        AeCtr::new(&key).unwrap().xor(&mut whole);
        assert_ne!(whole, data);
        // Ragged chunks (1, 7, 16, 33, …) must agree with one-shot.
        let mut chunked = data.clone();
        let mut c = AeCtr::new(&key).unwrap();
        let mut at = 0usize;
        for (i, step) in [1usize, 7, 16, 33, 5, 100].iter().cycle().enumerate() {
            let _ = i;
            if at >= chunked.len() {
                break;
            }
            let end = (at + step).min(chunked.len());
            c.xor(&mut chunked[at..end]);
            at = end;
        }
        assert_eq!(chunked, whole);
        AeCtr::new(&key).unwrap().xor(&mut chunked);
        assert_eq!(chunked, data);
    }

    #[test]
    fn ae_derive_shapes() {
        for (strength, (kl, sl)) in [(1u8, (16usize, 8usize)), (2, (24, 12)), (3, (32, 16))] {
            assert_eq!(ae_strength_lens(strength), Some((kl, sl)));
            let salt = vec![9u8; sl];
            let k = ae_derive(b"pw", &salt, kl);
            assert_eq!(k.enc_key.len(), kl);
            assert_eq!(k.mac_key.len(), kl);
        }
        assert_eq!(ae_strength_lens(0), None);
        assert_eq!(ae_strength_lens(4), None);
    }
}
