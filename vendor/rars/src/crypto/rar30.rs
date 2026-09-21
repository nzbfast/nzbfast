use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::Aes128;
use sha1::{Digest, Sha1};
use std::str;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// SHA-1 iterations over the password seed.
const KDF_ITERATIONS: usize = 0x40000;

/// One IV byte is sampled every this many iterations, sixteen in all.
const IV_SAMPLE_STRIDE: usize = KDF_ITERATIONS / 16;

/// Iterations materialised at once on the constant-seed path. One fixed
/// allocation, at most 67 bytes an iteration, so it stays in L1.
const BATCH_ITERATIONS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    NonUtf8Password,
    UnalignedInput,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonUtf8Password => f.write_str("RAR 3.x password is not UTF-8"),
            Self::UnalignedInput => f.write_str("RAR 3.x AES input is not block aligned"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, ZeroizeOnDrop)]
pub struct Rar30Cipher {
    cipher: Aes128,
    iv: [u8; 16],
}

impl Rar30Cipher {
    pub fn new(password: &[u8], salt: Option<[u8; 8]>) -> Result<Self> {
        let (mut key, iv) = derive_key_iv(password, salt)?;
        let cipher = Aes128::new(&key.into());
        key.zeroize();
        Ok(Self { cipher, iv })
    }

    pub fn decrypt_in_place(&mut self, data: &mut [u8]) -> Result<()> {
        if !data.len().is_multiple_of(16) {
            return Err(Error::UnalignedInput);
        }
        for block in data.chunks_exact_mut(16) {
            self.decrypt_block(block);
        }
        Ok(())
    }

    pub fn encrypt_in_place(&mut self, data: &mut [u8]) -> Result<()> {
        if !data.len().is_multiple_of(16) {
            return Err(Error::UnalignedInput);
        }
        for block in data.chunks_exact_mut(16) {
            self.encrypt_block(block);
        }
        Ok(())
    }

    fn encrypt_block(&mut self, block: &mut [u8]) {
        for (byte, iv_byte) in block.iter_mut().zip(self.iv) {
            *byte ^= iv_byte;
        }
        let block: &mut [u8; 16] = block.try_into().expect("AES block size");
        self.cipher.encrypt_block(block.into());
        self.iv.copy_from_slice(block);
    }

    fn decrypt_block(&mut self, block: &mut [u8]) {
        let ciphertext: [u8; 16] = block.try_into().expect("AES block size");
        let block: &mut [u8; 16] = block.try_into().expect("AES block size");
        self.cipher.decrypt_block(block.into());
        for (byte, iv_byte) in block.iter_mut().zip(self.iv) {
            *byte ^= iv_byte;
        }
        self.iv = ciphertext;
    }
}

/// Derive the AES-128 key and CBC IV for `password` and `salt`.
///
/// The seed is the password as UTF-16LE followed by the salt. One running
/// SHA-1 absorbs the seed and then a 3-byte little-endian iteration counter,
/// `KDF_ITERATIONS` times; the last byte of the running digest is sampled into
/// the IV every `IV_SAMPLE_STRIDE` iterations, counter included, and the final
/// digest's first four big-endian words, each byte-reversed, are the key.
///
/// A seed longer than one SHA-1 block also rewrites parts of itself as it is
/// absorbed (see `rewrite_interior_blocks`). That is RAR's behaviour, and
/// archives made with a long password do not open without it.
fn derive_key_iv(password: &[u8], salt: Option<[u8; 8]>) -> Result<([u8; 16], [u8; 16])> {
    let password = str::from_utf8(password).map_err(|_| Error::NonUtf8Password)?;
    // Sized for the worst case, two UTF-16 bytes per UTF-8 byte, so no
    // reallocation leaves an unzeroised copy of the seed behind.
    let mut input = Zeroizing::new(Vec::with_capacity(password.len() * 2 + 8 + 3));
    for code_unit in password.encode_utf16() {
        input.extend_from_slice(&code_unit.to_le_bytes());
    }
    if let Some(salt) = salt {
        input.extend_from_slice(&salt);
    }
    let seed_len = input.len();
    // One iteration's input is the seed then its counter, fed as one update.
    input.extend_from_slice(&[0; 3]);
    let step = input.len();

    let mut hash = Sha1::new();
    let mut iv = [0u8; 16];
    if seed_len > 64 {
        // The seed rewrites itself as it is absorbed, so every iteration has
        // its own seed image and the input goes in one iteration at a time.
        for iteration in 0..KDF_ITERATIONS {
            write_counter(&mut input[seed_len..], iteration);
            hash.update(&input[..]);
            rewrite_interior_blocks(&mut input[..seed_len], iteration as u64 * step as u64);
            sample_iv(&hash, iteration, &mut iv);
        }
    } else {
        // Nothing is ever rewritten here, so every iteration feeds the same
        // seed and only its three counter bytes differ. One image of
        // `BATCH_ITERATIONS` iterations is built once and the counters are
        // rewritten in place between updates, which feeds SHA-1 in kilobytes
        // rather than in 27-byte calls without copying the seed again.
        // (Measured 15 Sep 2026: a batch that re-copies the seed every
        // iteration is SLOWER than one update per iteration, 4.03 ms against
        // 3.50 ms - the copy, not the call, was what cost.)
        let mut batch = Zeroizing::new(input.repeat(BATCH_ITERATIONS));
        for sample in 0..16 {
            // The sampled iteration goes in alone: the IV byte is the running
            // digest with this iteration's counter absorbed and no more.
            let first = sample * IV_SAMPLE_STRIDE;
            write_counter(&mut batch[seed_len..], first);
            hash.update(&batch[..step]);
            sample_iv(&hash, first, &mut iv);

            let mut done = 1;
            while done < IV_SAMPLE_STRIDE {
                let run = BATCH_ITERATIONS.min(IV_SAMPLE_STRIDE - done);
                for slot in 0..run {
                    write_counter(&mut batch[slot * step + seed_len..], first + done + slot);
                }
                hash.update(&batch[..run * step]);
                done += run;
            }
        }
    }

    let mut digest = hash.finalize();
    let mut key = [0u8; 16];
    for (key_word, digest_word) in key.chunks_exact_mut(4).zip(digest.chunks_exact(4)) {
        for (out, &byte) in key_word.iter_mut().zip(digest_word.iter().rev()) {
            *out = byte;
        }
    }
    digest[..].zeroize();
    Ok((key, iv))
}

/// Write iteration `iteration`'s counter, its low 24 bits little-endian, over
/// the first three bytes of `counter`.
fn write_counter(counter: &mut [u8], iteration: usize) {
    counter[0] = iteration as u8;
    counter[1] = (iteration >> 8) as u8;
    counter[2] = (iteration >> 16) as u8;
}

/// Take one IV byte from the running digest, if `iteration` is a sampling one.
///
/// The byte is the last of a digest of everything absorbed so far, so the hash
/// is cloned rather than finalized.
fn sample_iv(hash: &Sha1, iteration: usize, iv: &mut [u8; 16]) {
    if iteration.is_multiple_of(IV_SAMPLE_STRIDE) {
        let mut sample = hash.clone().finalize();
        iv[iteration / IV_SAMPLE_STRIDE] = sample[19];
        sample[..].zeroize();
    }
}

/// Rewrite the seed after one iteration has absorbed it.
///
/// `stream_offset` is how many bytes the hash had absorbed before this
/// iteration's seed. Every 64-byte block of the hash input that starts
/// strictly after the seed's first byte and ends inside the seed is replaced,
/// once absorbed, by `schedule_tail` of itself; later iterations feed the
/// rewritten bytes. The blocks are disjoint, so their order does not matter.
/// A seed of 64 bytes or fewer holds no such block.
fn rewrite_interior_blocks(seed: &mut [u8], stream_offset: u64) {
    // The first block boundary strictly after the seed's first byte.
    let mut start = 64 - (stream_offset % 64) as usize;
    while start + 64 <= seed.len() {
        schedule_tail(&mut seed[start..start + 64]);
        start += 64;
    }
}

/// Run a 64-byte block through SHA-1's message expansion and write the last
/// sixteen expansion words, `W[64..80]`, back over it little-endian.
fn schedule_tail(block: &mut [u8]) {
    // A rolling window of sixteen words: slot `t % 16` holds `W[t]`, so after
    // the last step slot `j` holds `W[64 + j]`.
    let mut window = [0u32; 16];
    for (word, bytes) in window.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }
    // Rounds 16 to 80, in four passes over the window. Within a pass slot `j`
    // holds `W[t]` for `t = base + j`, so the taps `t - 3`, `t - 8` and
    // `t - 14` are the fixed slots below and the indices fold away.
    for _ in 0..4 {
        for j in 0..16 {
            window[j] =
                (window[(j + 13) % 16] ^ window[(j + 8) % 16] ^ window[(j + 2) % 16] ^ window[j])
                    .rotate_left(1);
        }
    }
    for (bytes, word) in block.chunks_exact_mut(4).zip(window.iter()) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
    window.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_kdf_material(password: &[u8], salt: Option<[u8; 8]>) -> Vec<u8> {
        let mut raw = Vec::with_capacity(password.len() * 2 + 8);
        let password = str::from_utf8(password).unwrap();
        for code_unit in password.encode_utf16() {
            raw.extend_from_slice(&code_unit.to_le_bytes());
        }
        if let Some(salt) = salt {
            raw.extend_from_slice(&salt);
        }
        raw
    }

    #[test]
    fn rar30_aes_encrypt_decrypt_round_trips_blocks() {
        let salt = Some([1, 2, 3, 4, 5, 6, 7, 8]);
        let mut data = *b"0123456789abcdefRAR AES CBC data";
        let plain = data;

        Rar30Cipher::new(b"password", salt)
            .unwrap()
            .encrypt_in_place(&mut data)
            .unwrap();
        assert_eq!(
            data,
            [
                0x5e, 0x59, 0xce, 0xa1, 0x16, 0xca, 0xa2, 0x1d, 0x4d, 0xc5, 0x05, 0xeb, 0xa9, 0x3f,
                0x7b, 0xcd, 0x0d, 0x04, 0xff, 0xea, 0x60, 0x67, 0x3d, 0xaf, 0x6a, 0x8f, 0x02, 0xb2,
                0x03, 0xc8, 0x7d, 0xde,
            ]
        );

        Rar30Cipher::new(b"password", salt)
            .unwrap()
            .decrypt_in_place(&mut data)
            .unwrap();
        assert_eq!(data, plain);
    }

    #[test]
    fn rar30_aes_round_trips_with_long_password_slow_path() {
        // Password long enough that utf-16(password) + 8-byte salt > 64,
        // so the seed rewrites itself as it is absorbed.
        let password = b"this-password-is-deliberately-long-enough-to-exceed-64-bytes-utf16";
        let salt = Some(*b"longsalt");
        let mut data = *b"0123456789abcdefRAR AES CBC data";
        let plain = data;

        Rar30Cipher::new(password, salt)
            .unwrap()
            .encrypt_in_place(&mut data)
            .unwrap();
        assert_eq!(
            data,
            [
                0xb9, 0xa7, 0xac, 0x4b, 0x81, 0x0a, 0x5c, 0xf1, 0x6e, 0xd4, 0x5a, 0x4c, 0xbc, 0x1e,
                0x2e, 0xef, 0x53, 0x7b, 0x89, 0x63, 0x7a, 0xc5, 0x7a, 0x1e, 0xfc, 0x43, 0x3c, 0x18,
                0xea, 0xfd, 0x54, 0xed,
            ]
        );

        Rar30Cipher::new(password, salt)
            .unwrap()
            .decrypt_in_place(&mut data)
            .unwrap();
        assert_eq!(data, plain);
    }

    #[test]
    fn rar30_aes_rejects_partial_tail() {
        let mut data = *b"partial block!!";

        assert_eq!(
            Rar30Cipher::new(b"password", None)
                .unwrap()
                .encrypt_in_place(&mut data),
            Err(Error::UnalignedInput)
        );
        assert_eq!(
            Rar30Cipher::new(b"password", None)
                .unwrap()
                .decrypt_in_place(&mut data),
            Err(Error::UnalignedInput)
        );
    }

    #[test]
    fn rejects_non_utf8_passwords() {
        assert!(matches!(
            Rar30Cipher::new(b"\xffpassword", None),
            Err(Error::NonUtf8Password)
        ));
    }

    /// A plain reference for seeds under 64 bytes, where nothing is ever
    /// rewritten: materialise the whole hash input and digest prefixes of it.
    fn reference_short_seed(seed: &[u8]) -> ([u8; 16], [u8; 16]) {
        let mut stream = Vec::with_capacity(KDF_ITERATIONS * (seed.len() + 3));
        let mut iv = [0u8; 16];
        for iteration in 0..KDF_ITERATIONS {
            stream.extend_from_slice(seed);
            stream.extend_from_slice(&(iteration as u32).to_le_bytes()[..3]);
            if iteration % IV_SAMPLE_STRIDE == 0 {
                iv[iteration / IV_SAMPLE_STRIDE] = Sha1::digest(&stream)[19];
            }
        }
        let digest = Sha1::digest(&stream);
        let mut key = [0u8; 16];
        for word in 0..4 {
            for byte in 0..4 {
                key[4 * word + byte] = digest[4 * word + 3 - byte];
            }
        }
        (key, iv)
    }

    #[test]
    fn short_seeds_match_a_plain_repeated_seed_reference() {
        for (password, salt) in [
            (b"".as_slice(), None),
            (b"password".as_slice(), Some(*b"rarsalt!")),
            ("páss".as_bytes(), Some([1, 2, 3, 4, 5, 6, 7, 8])),
        ] {
            let seed = raw_kdf_material(password, salt);
            assert!(seed.len() < 64, "case should stay under one block");
            assert_eq!(
                derive_key_iv(password, salt).unwrap(),
                reference_short_seed(&seed)
            );
        }
    }

    /// The message-schedule tail against SHA-1's expansion written out in
    /// full: an all-zero block stays zero, and patterned blocks give the words
    /// an 80-word schedule computed the long way gives.
    #[test]
    fn schedule_tail_matches_the_full_message_expansion() {
        let mut zero = [0u8; 64];
        schedule_tail(&mut zero);
        assert_eq!(zero, [0u8; 64]);

        for seed in 0..8u8 {
            let block: Vec<u8> = (0..64u8).map(|i| i.wrapping_mul(37) ^ seed).collect();
            let mut words = [0u32; 80];
            for (t, bytes) in block.chunks_exact(4).enumerate() {
                words[t] = u32::from_be_bytes(bytes.try_into().unwrap());
            }
            for t in 16..80 {
                words[t] =
                    (words[t - 3] ^ words[t - 8] ^ words[t - 14] ^ words[t - 16]).rotate_left(1);
            }
            let expected: Vec<u8> = words[64..].iter().flat_map(|w| w.to_le_bytes()).collect();
            let mut tail = block.clone();
            schedule_tail(&mut tail);
            assert_eq!(tail, expected);
        }
    }

    /// Every sweep case: ASCII passwords of 0 to 200 bytes, and non-ASCII ones
    /// cycling 2-, 3- and 4-byte UTF-8 characters (the last a surrogate pair
    /// in UTF-16) up to 200 bytes, each with and without a salt.
    fn sweep_cases() -> Vec<(Vec<u8>, Option<[u8; 8]>)> {
        let mut passwords: Vec<Vec<u8>> = (0..=200usize)
            .map(|len| (0..len).map(|i| b'!' + (i * 7 % 94) as u8).collect())
            .collect();
        let alphabet = ['é', '€', '𝄞', 'ß', 'ж'];
        let mut text = String::new();
        for &ch in alphabet.iter().cycle() {
            if text.len() + ch.len_utf8() > 200 {
                break;
            }
            text.push(ch);
            passwords.push(text.as_bytes().to_vec());
        }
        passwords
            .into_iter()
            .flat_map(|password| {
                [
                    (password.clone(), None),
                    (password, Some(*b"\x9asalt\x00\xff!")),
                ]
            })
            .collect()
    }

    /// A key derivation: the one under test, or a reference.
    type Derive = fn(&[u8], Option<[u8; 8]>) -> Result<([u8; 16], [u8; 16])>;

    /// Derive every case across threads, in case order.
    fn derive_all(
        cases: &[(Vec<u8>, Option<[u8; 8]>)],
        derive: Derive,
    ) -> Vec<([u8; 16], [u8; 16])> {
        let threads = std::thread::available_parallelism().map_or(4, |n| n.get().min(16));
        let mut results = vec![([0u8; 16], [0u8; 16]); cases.len()];
        let per_thread = cases.len().div_ceil(threads);
        std::thread::scope(|scope| {
            for (chunk, out) in cases.chunks(per_thread).zip(results.chunks_mut(per_thread)) {
                scope.spawn(move || {
                    for ((password, salt), slot) in chunk.iter().zip(out) {
                        *slot = derive(password, *salt).unwrap();
                    }
                });
            }
        });
        results
    }

    /// Hex of a derived key followed by its IV.
    fn key_iv_hex((key, iv): &([u8; 16], [u8; 16])) -> String {
        key.iter().chain(iv).map(|b| format!("{b:02x}")).collect()
    }

    /// The whole sweep against the digest the replaced derivation produced
    /// when it was still in the tree (SHA-1 over every key then IV, in case
    /// order). Heavy: run in release with `--ignored`.
    #[test]
    #[ignore = "about 45 GB of SHA-1; run in release"]
    fn derivation_sweep_matches_its_frozen_digest() {
        let cases = sweep_cases();
        assert_eq!(cases.len(), 556);
        let mut sweep = Sha1::new();
        for (key, iv) in derive_all(&cases, derive_key_iv) {
            sweep.update(key);
            sweep.update(iv);
        }
        let digest: String = sweep
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(digest, "22207d9079e1b6d9eb27dc7c2fbd975e49ea999b");
    }

    /// Six sweep cases pinned to the replaced derivation's answers: either
    /// side of the long-seed rewrite threshold, a 64-byte password and the
    /// longest non-ASCII one.
    #[test]
    fn derivation_matches_frozen_answers_for_pinned_sweep_cases() {
        let cases = sweep_cases();
        for (index, expected) in [
            (
                57,
                "2aa1e33e5850f513b1ff6b7df357c9bde9afd39d68bbe3a77b4c34a1331f6106",
            ),
            (
                59,
                "de28e1820943f9a9fb615845f683fa8462bf37f05388f5e36480eed0ec57f8b8",
            ),
            (
                66,
                "af2b35595b2a4c59e1f82a140747147f1839c1cef0623d8d5d5ce36f160a03f0",
            ),
            (
                67,
                "bfaa449548ca6bc6536874ba5d6c7cdfaf4b98aa9f80c919974286894a742ad4",
            ),
            (
                129,
                "e0594440b57770597570ac3eb4bf4f4a485b8dceb806c1551386fe84b49a5606",
            ),
            (
                555,
                "c0350c91073c6931e98c91ff85d1fa9c6940700bdfd348d1dd9abf243d626063",
            ),
        ] {
            let (password, salt) = &cases[index];
            let derived = derive_key_iv(password, *salt).unwrap();
            assert_eq!(
                key_iv_hex(&derived),
                expected,
                "case {index}: {} bytes, salt {}",
                password.len(),
                salt.is_some()
            );
        }
    }

    /// Key derivation cost for a short seed, the long-seed rewrite path and a
    /// 200-byte password. Timing only; run in release with `--ignored
    /// --nocapture` and read the best of eleven.
    #[test]
    #[ignore = "timing harness, run by hand in release"]
    fn rar30_key_derivation_timing() {
        let long = [b'x'; 200];
        for (label, password, salt) in [
            ("short", b"password".as_slice(), Some(*b"rarsalt!")),
            (
                "long",
                b"this-password-is-deliberately-long-enough-to-exceed-64-bytes-utf16".as_slice(),
                Some(*b"longsalt"),
            ),
            ("200 B", long.as_slice(), Some(*b"longsalt")),
        ] {
            let mut best = f64::MAX;
            for _ in 0..11 {
                let start = std::time::Instant::now();
                let cipher = Rar30Cipher::new(password, salt).unwrap();
                best = best.min(start.elapsed().as_secs_f64());
                drop(cipher);
            }
            println!("rar30 kdf {label}: best {:.2} ms", best * 1e3);
        }
    }
}
