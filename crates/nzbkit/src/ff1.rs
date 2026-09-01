//! FF1 format-preserving encryption (NIST SP 800-38G) over AES-256,
//! for the Tensai75 yEnc control-lines draft (`yencrypt`'s FF1 half).
//!
//! Hand-rolled rather than a crate: the only maintained Rust FF1 crate
//! (`fpe` 0.6.1, 2023) is two cipher-stack majors behind this tree, and
//! the draft needs a custom radix-253 alphabet, which is the part most
//! wrappers get wrong. The core is validated against NIST's own
//! FF1-AES256 samples 7-9 (ff1samples.pdf) in the tests below; the
//! radix-253 use rides that core plus round-trip pins in `yencrypt`.
//!
//! Digits are `u8` numeral values `0..radix`, radix 2..=256 - wide
//! enough for the draft's 253-symbol alphabet, and the byte<->numeral
//! bijection is the CALLER's (it is spec vocabulary, not FF1's).

use aes::Aes256;
use aes::cipher::array::Array;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use num_bigint::BigUint;

/// FF1 with a fixed key and radix. One instance per (key, radix);
/// encrypt/decrypt take the per-call tweak the draft derives per line.
pub struct Ff1 {
    cipher: Aes256,
    radix: u32,
}

/// Why an input cannot be enciphered. FF1's domain bounds are part of
/// the standard: too-short inputs leak through small-domain attacks, so
/// they are a refusal, never a truncation or a pass-through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ff1Error {
    /// Fewer than 2 digits, or radix^n < 100 (SP 800-38G minlen rule).
    TooShort,
    /// A digit at or above the radix.
    DigitOutOfRange,
}

impl Ff1 {
    /// Radix must be 2..=256 (u8 digits); the draft uses 253.
    pub fn new(key: &[u8; 32], radix: u32) -> Ff1 {
        assert!((2..=256).contains(&radix), "radix {radix} out of range");
        let cipher = Aes256::new_from_slice(key).expect("AES-256 accepts a 32-byte key");
        Ff1 { cipher, radix }
    }

    /// FF1.Encrypt(K, T, X). Same-length output, digits in `0..radix`.
    pub fn encrypt(&self, tweak: &[u8], x: &[u8]) -> Result<Vec<u8>, Ff1Error> {
        self.feistel(tweak, x, true)
    }

    /// FF1.Decrypt(K, T, X) - the exact inverse of [`Ff1::encrypt`].
    pub fn decrypt(&self, tweak: &[u8], x: &[u8]) -> Result<Vec<u8>, Ff1Error> {
        self.feistel(tweak, x, false)
    }

    /// Both directions share one Feistel body: the round order and the
    /// add-vs-subtract at step 6.vi are the only differences, so keeping
    /// them in one function is what keeps them inverses under edit.
    fn feistel(&self, tweak: &[u8], x: &[u8], forward: bool) -> Result<Vec<u8>, Ff1Error> {
        let radix = self.radix;
        let n = x.len();
        // Domain bounds: n >= 2 and radix^n >= 100 (minlen), per the
        // standard's prerequisites. Digits must be numerals of the radix.
        if n < 2 || (BigUint::from(radix)).pow(n as u32) < BigUint::from(100u32) {
            return Err(Ff1Error::TooShort);
        }
        if x.iter().any(|&d| u32::from(d) >= radix) {
            return Err(Ff1Error::DigitOutOfRange);
        }
        let t = tweak.len();
        let u = n / 2;
        let v = n - u;
        // b = ceil(ceil(v * log2(radix)) / 8), computed exactly:
        // NUMradix(B) < radix^v, and bits(radix^v - 1) IS that ceiling
        // (equal also when radix^v is a power of two).
        let rv = BigUint::from(radix).pow(v as u32);
        let b = ((&rv - 1u32).bits() as usize).div_ceil(8);
        let d = 4 * b.div_ceil(4) + 4;
        // P: [1]1 [2]1 [1]1 [radix]3 [10]1 [u mod 256]1 [n]4 [t]4.
        let mut p = Vec::with_capacity(16);
        p.extend_from_slice(&[1, 2, 1]);
        p.extend_from_slice(&radix.to_be_bytes()[1..4]);
        p.push(10);
        p.push(u as u8);
        p.extend_from_slice(&(n as u32).to_be_bytes());
        p.extend_from_slice(&(t as u32).to_be_bytes());
        let pad = (16 - ((t + b + 1) % 16)) % 16;

        let r_u = BigUint::from(radix).pow(u as u32);
        let (mut a, mut bh) = (x[..u].to_vec(), x[u..].to_vec());
        for round in 0..10u8 {
            let i = if forward { round } else { 9 - round };
            // Q = T || [0]^pad || [i]1 || [NUM(active half)]b. Encrypt
            // reads B here; decrypt reads A (the standard's reversal).
            let active = if forward { &bh } else { &a };
            let mut q = Vec::with_capacity(t + pad + 1 + b);
            q.extend_from_slice(tweak);
            q.resize(t + pad, 0);
            q.push(i);
            let num = BigUint::from_radix_be(active, radix).expect("digits checked above");
            let num_bytes = num.to_bytes_be();
            q.resize(q.len() + b - num_bytes.len().min(b), 0);
            q.extend_from_slice(&num_bytes[num_bytes.len().saturating_sub(b)..]);
            let r = self.prf(&p, &q);
            // S = first d bytes of R || CIPH(R xor [1]16) || CIPH(R xor
            // [2]16) || ...
            let mut s = r.to_vec();
            let mut j = 1u128;
            while s.len() < d {
                let mut blk = Array::<u8, aes::cipher::consts::U16>::default();
                let jb = j.to_be_bytes();
                for (o, (rb, xb)) in r.iter().zip(jb.iter()).enumerate() {
                    blk[o] = rb ^ xb;
                }
                self.cipher.encrypt_block(&mut blk);
                s.extend_from_slice(&blk);
                j += 1;
            }
            let y = BigUint::from_bytes_be(&s[..d]);
            let (m, rm) = if i % 2 == 0 { (u, &r_u) } else { (v, &rv) };
            let changed = if forward { &a } else { &bh };
            let base = BigUint::from_radix_be(changed, radix).expect("digits checked above");
            let c = if forward {
                (base + y) % rm
            } else {
                (base + rm - (y % rm)) % rm
            };
            let mut digits = c.to_radix_be(radix);
            let mut padded = vec![0u8; m - digits.len()];
            padded.append(&mut digits);
            if forward {
                a = std::mem::replace(&mut bh, padded);
            } else {
                bh = std::mem::replace(&mut a, padded);
            }
        }
        let mut out = a;
        out.extend_from_slice(&bh);
        Ok(out)
    }

    /// PRF(P || Q): AES-CBC-MAC with a zero IV. `p` is one block; `q`
    /// is a whole number of blocks by construction of the padding.
    fn prf(&self, p: &[u8], q: &[u8]) -> [u8; 16] {
        let mut y = Array::<u8, aes::cipher::consts::U16>::default();
        for chunk in p.chunks(16).chain(q.chunks(16)) {
            for (o, byte) in chunk.iter().enumerate() {
                y[o] ^= byte;
            }
            self.cipher.encrypt_block(&mut y);
        }
        y.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The NIST FF1-AES256 sample key (ff1samples.pdf, samples 7-9).
    const KEY: [u8; 32] = [
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F,
        0x3C, 0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F, 0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC,
        0x6A, 0x94,
    ];

    fn digits(s: &str) -> Vec<u8> {
        s.chars()
            .map(|c| c.to_digit(36).expect("sample digits are 0-9a-z") as u8)
            .collect()
    }

    #[test]
    fn nist_sample_7_radix10_empty_tweak() {
        let ff1 = Ff1::new(&KEY, 10);
        let ct = ff1.encrypt(&[], &digits("0123456789")).unwrap();
        assert_eq!(ct, digits("6657667009"));
        let pt = ff1.decrypt(&[], &ct).unwrap();
        assert_eq!(pt, digits("0123456789"));
    }

    #[test]
    fn nist_sample_8_radix10_with_tweak() {
        let tweak = [0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30];
        let ff1 = Ff1::new(&KEY, 10);
        let ct = ff1.encrypt(&tweak, &digits("0123456789")).unwrap();
        assert_eq!(ct, digits("1001623463"));
        let pt = ff1.decrypt(&tweak, &ct).unwrap();
        assert_eq!(pt, digits("0123456789"));
    }

    #[test]
    fn nist_sample_9_radix36() {
        let tweak = [
            0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37,
        ];
        let ff1 = Ff1::new(&KEY, 36);
        let ct = ff1.encrypt(&tweak, &digits("0123456789abcdefghi")).unwrap();
        assert_eq!(ct, digits("xs8a0azh2avyalyzuwd"));
        let pt = ff1.decrypt(&tweak, &ct).unwrap();
        assert_eq!(pt, digits("0123456789abcdefghi"));
    }

    #[test]
    fn radix_253_round_trips_across_lengths_and_tweaks() {
        let ff1 = Ff1::new(&KEY, 253);
        // Odd and even lengths exercise both u/v splits; the long case
        // is a realistic `=ybegin` line's digit count.
        for len in [2usize, 3, 13, 40, 41, 200] {
            let pt: Vec<u8> = (0..len).map(|i| ((i * 89) % 253) as u8).collect();
            let ct = ff1
                .encrypt(b"\x01\x02\x03\x04\x05\x06\x07\x08", &pt)
                .unwrap();
            assert_eq!(ct.len(), pt.len(), "FF1 is length-preserving");
            assert!(ct.iter().all(|&d| u32::from(d) < 253));
            assert_ne!(ct, pt, "len {len} ciphertext equals plaintext");
            let back = ff1
                .decrypt(b"\x01\x02\x03\x04\x05\x06\x07\x08", &ct)
                .unwrap();
            assert_eq!(back, pt, "len {len} did not round-trip");
            // A different tweak must not decrypt to the same plaintext.
            let other = ff1
                .decrypt(b"\x01\x02\x03\x04\x05\x06\x07\x09", &ct)
                .unwrap();
            assert_ne!(other, pt, "tweak did not separate len {len}");
        }
    }

    #[test]
    fn domain_bounds_refuse_rather_than_truncate() {
        let ff1 = Ff1::new(&KEY, 10);
        assert_eq!(ff1.encrypt(&[], &[1]), Err(Ff1Error::TooShort));
        // radix 10, n=2: 100 >= 100, allowed - the boundary itself.
        assert!(ff1.encrypt(&[], &[1, 2]).is_ok());
        let ff1b = Ff1::new(&KEY, 2);
        // radix 2, n=6: 64 < 100 refused; n=7: 128 passes.
        assert_eq!(
            ff1b.encrypt(&[], &[1, 0, 1, 0, 1, 0]),
            Err(Ff1Error::TooShort)
        );
        assert!(ff1b.encrypt(&[], &[1, 0, 1, 0, 1, 0, 1]).is_ok());
        assert_eq!(
            ff1.encrypt(&[], &[1, 10]),
            Err(Ff1Error::DigitOutOfRange),
            "a digit equal to the radix is not a numeral"
        );
    }
}
