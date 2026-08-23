//! RAR decryption: key schedules + CBC helpers for both wire formats.
//!
//! Obfuscated releases are overwhelmingly encrypted STORE archives - the
//! data is already-compressed media, so `-m0 -p`/`-hp` is the norm.
//! Decrypting those natively keeps them on the one-pass in-stream
//! extraction path; the embedded unrar is only needed for genuinely
//! COMPRESSED sets (full RAR decompression is explicitly out of scope).
//!
//! RAR5 key schedule (matches unrar's `CryptData::SetKey` for RAR5):
//! PBKDF2-HMAC-SHA256 over the UTF-8 password with a 16-byte salt and
//! 2^lg2_count iterations yields the AES-256 key; the SAME PBKDF2 block-1
//! chain continued 16 more rounds yields the hash key (tweaked-checksum
//! MAC), and 16 further rounds the password-check source, XOR-folded to 8
//! bytes. The stored 12-byte check value is those 8 bytes plus the first 4
//! of their SHA-256 (a corruption guard, not a secret).
//!
//! RAR4 (RAR 3.0+, `unp_ver >= 29`) key schedule: 0x40000 rounds of SHA-1
//! over UTF-16LE(password) + an optional 8-byte salt + a 3-byte round
//! counter. The digest's first 16 bytes, byte-swapped per 32-bit word, are
//! the AES-128 key; one byte sampled from every 16th round's digest builds
//! the 16-byte CBC IV. Ported from the vendored rars fork
//! (`vendor/rars/src/crypto/rar30.rs`), which is unrar-validated - see the
//! KATs below, which pin this port against that fork's own vectors.
//!
//! The two schedules differ in every dimension that matters (AES width,
//! where the IV comes from, whether a pre-decrypt password check exists),
//! so callers work through [`AesKey`] and [`EntryKeys`] rather than
//! assuming a 32-byte key and a header-supplied IV.

use crate::sync::MutexExt;
use std::collections::HashMap;
use std::sync::Mutex;

use aes::cipher::array::Array;
use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use hmac::digest::KeyInit as MacKeyInit;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Block = Array<u8, aes::cipher::consts::U16>;

/// An AES key of whichever width the archive's format uses. Both are
/// driven in CBC with a 16-byte block, so everything above this type -
/// chaining, checkpointing, the re-encrypt shim, sharded finish passes -
/// is width-agnostic.
#[derive(Clone, PartialEq, Eq)]
pub enum AesKey {
    /// RAR5.
    Aes256([u8; 32]),
    /// RAR4 (RAR 3.0+).
    Aes128([u8; 16]),
}

/// Derived key material for one encrypted entry, in the form the
/// extractor needs: the AES key and the IV its CBC stream starts from.
///
/// RAR5 reads the IV out of the header's crypt record; RAR4 derives it
/// alongside the key, which is why the IV lives here and not on the
/// parsed crypt parameters.
#[derive(Clone, PartialEq, Eq)]
pub struct EntryKeys {
    pub(crate) aes: AesKey,
    pub(crate) iv: [u8; 16],
    /// RAR5 tweaked-checksum MAC key. `None` for RAR4, which has no
    /// tweaked-checksum flag at all - a RAR4 file header always stores
    /// the bare CRC32 of the PLAINTEXT.
    pub(crate) hash_key: Option<[u8; 32]>,
    /// RAR5 8-byte password check value. `None` for RAR4, which stores
    /// nothing a password can be tested against before decrypting - the
    /// reason RAR4 entries always take the unverified route (ciphertext
    /// assembly, checksum verdict at finish).
    pub(crate) psw_check: Option<[u8; 8]>,
}

/// View a 16-aligned byte buffer as AES blocks - the batched
/// `{en,de}crypt_blocks_mut` APIs let the backend pipeline several
/// blocks per call (4x on soft AES, ~1.2x on hardware; measured).
/// Array<u8, U16> is layout-identical to [u8; 16] (align 1), so
/// the cast is sound for any len % 16 == 0 slice.
fn as_blocks(data: &mut [u8]) -> &mut [Block] {
    debug_assert_eq!(data.len() % 16, 0);
    unsafe { core::slice::from_raw_parts_mut(data.as_mut_ptr().cast::<Block>(), data.len() / 16) }
}

/// Iteration exponents above this are hostile (unrar caps at 24 too):
/// 2^24 ≈ 16M HMAC rounds is already ~10 s of KDF.
pub const MAX_KDF_LG2: u8 = 24;

#[derive(Clone, PartialEq, Eq)]
pub struct Rar5Keys {
    /// AES-256 key.
    pub(crate) key: [u8; 32],
    /// Tweaked-checksum HMAC key: folds a plaintext CRC32 the way
    /// WinRAR stores it when the crypt record's tweaked flag is set (see
    /// [`mac_crc32`]), so such an entry's stored checksum still verifies
    /// the decrypted output.
    pub(crate) hash_key: [u8; 32],
    /// 8-byte password check value - compare against a header's stored
    /// check to reject a wrong password BEFORE writing garbage.
    pub psw_check: [u8; 8],
}

impl Rar5Keys {
    /// This key set in the width-agnostic form the CBC helpers take.
    pub fn aes(&self) -> AesKey {
        AesKey::Aes256(self.key)
    }
}

/// PBKDF2-HMAC-SHA256, block 1 only (RAR5 never needs more than 32
/// bytes), with the RAR twist: three outputs off one U-chain at
/// `count`, `count+16`, and `count+32` iterations.
fn pbkdf2_chain(password: &[u8], salt: &[u8; 16], lg2_count: u8) -> Rar5Keys {
    let count: u64 = 1u64 << lg2_count.min(MAX_KDF_LG2);
    let prf =
        <HmacSha256 as MacKeyInit>::new_from_slice(password).expect("hmac accepts any key length");
    // U1 = HMAC(pw, salt || INT_BE(1))
    let mut mac = prf.clone();
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    let mut u: [u8; 32] = mac.finalize().into_bytes().into();
    let mut t = u;
    let mut key = [0u8; 32];
    let mut hash_key = [0u8; 32];
    let mut check_src = [0u8; 32];
    let mut i: u64 = 1;
    for (target, out) in [
        (count, &mut key),
        (count + 16, &mut hash_key),
        (count + 32, &mut check_src),
    ] {
        while i < target {
            let mut mac = prf.clone();
            mac.update(&u);
            u = mac.finalize().into_bytes().into();
            for (tb, ub) in t.iter_mut().zip(u.iter()) {
                *tb ^= ub;
            }
            i += 1;
        }
        *out = t;
    }
    let mut psw_check = [0u8; 8];
    for (i, b) in check_src.iter().enumerate() {
        psw_check[i % 8] ^= b;
    }
    Rar5Keys {
        key,
        hash_key,
        psw_check,
    }
}

/// KDF cache: a multi-volume set repeats ONE (salt, count) pair in every
/// volume's file header, and header-encrypted sets run one KDF per
/// volume - either way the same tuple recurs, and at 2^15 HMAC rounds a
/// miss costs ~10 ms inside the extractor's routing lock. Bounded: a
/// hostile NZB can't grow it past a few hundred entries.
static KDF_CACHE: Mutex<Option<HashMap<(Vec<u8>, [u8; 16], u8), Rar5Keys>>> = Mutex::new(None);
const KDF_CACHE_MAX: usize = 512;

/// Derive (or fetch cached) RAR5 keys. Returns None for a hostile
/// iteration count.
pub fn derive_keys(password: &str, salt: &[u8; 16], lg2_count: u8) -> Option<Rar5Keys> {
    if lg2_count > MAX_KDF_LG2 {
        return None;
    }
    let ck = (password.as_bytes().to_vec(), *salt, lg2_count);
    {
        let g = KDF_CACHE.lock_ok();
        if let Some(hit) = g.as_ref().and_then(|m| m.get(&ck)) {
            return Some(hit.clone());
        }
    }
    let keys = pbkdf2_chain(password.as_bytes(), salt, lg2_count);
    let mut g = KDF_CACHE.lock_ok();
    let m = g.get_or_insert_with(HashMap::new);
    if m.len() >= KDF_CACHE_MAX {
        m.clear();
    }
    m.insert(ck, keys.clone());
    Some(keys)
}

// ---------------------------------------------------------------------------
// RAR4 (RAR 3.0+) key schedule - AES-128, SHA-1 based, IV from the KDF.
// Ported from vendor/rars/src/crypto/rar30.rs (= unrar's CRYPT_RAR30).
// ---------------------------------------------------------------------------

/// Fixed round count of the RAR3 key schedule (unrar's `CRYPT3_ROUNDS`).
const RAR4_ROUNDS: u32 = 0x40000;

/// AES-128 key + CBC IV for a RAR4 encrypted entry. Unlike RAR5 there is
/// no check value and no MAC key: the schedule produces exactly these two
/// outputs and the format stores nothing else.
#[derive(Clone, PartialEq, Eq)]
pub struct Rar4Keys {
    pub(crate) key: [u8; 16],
    pub(crate) iv: [u8; 16],
}

/// Its own cache: the RAR3 schedule is 0x40000 SHA-1 rounds (~50 ms), and
/// a `-hp` volume re-derives per HEADER, so a miss per block would cost
/// seconds per volume. Keyed on (password, salt) - a set repeats one salt
/// across every volume and every header.
static KDF4_CACHE: Mutex<Option<HashMap<(Vec<u8>, Option<[u8; 8]>), Rar4Keys>>> = Mutex::new(None);

/// Derive (or fetch cached) RAR4 keys. `salt` is the file header's 8-byte
/// salt when the `FHD_SALT` flag is set, or the 8 bytes preceding an
/// encrypted header block; `None` for the (legacy) unsalted shape.
pub fn derive_keys_v4(password: &str, salt: Option<[u8; 8]>) -> Rar4Keys {
    let ck = (password.as_bytes().to_vec(), salt);
    {
        let g = KDF4_CACHE.lock_ok();
        if let Some(hit) = g.as_ref().and_then(|m| m.get(&ck)) {
            return hit.clone();
        }
    }
    let keys = rar4_schedule(password, salt);
    let mut g = KDF4_CACHE.lock_ok();
    let m = g.get_or_insert_with(HashMap::new);
    if m.len() >= KDF_CACHE_MAX {
        m.clear();
    }
    m.insert(ck, keys.clone());
    keys
}

fn rar4_schedule(password: &str, salt: Option<[u8; 8]>) -> Rar4Keys {
    let mut raw: Vec<u8> = Vec::with_capacity(password.len() * 2 + 8);
    for unit in password.encode_utf16() {
        raw.extend_from_slice(&unit.to_le_bytes());
    }
    if let Some(s) = salt {
        raw.extend_from_slice(&s);
    }
    // RAR3 mutates the password buffer in place, but only once the
    // repeated KDF input has crossed a COMPLETE 64-byte SHA-1 block. While
    // UTF-16(password)+salt stays under 64 bytes that can never happen, so
    // the plain hash is exactly equivalent and much simpler. The rars fork
    // splits the same two ways and pins their agreement with a test.
    if raw.len() < 64 {
        rar4_schedule_short(&raw)
    } else {
        rar4_schedule_long(&mut raw)
    }
}

/// Fold the finished SHA-1 digest into an AES-128 key: the first 16 bytes,
/// byte-reversed within each 32-bit word (unrar reads them as LE u32s).
fn rar4_key_from_digest(digest: &[u8]) -> [u8; 16] {
    let mut key = [0u8; 16];
    for (w, chunk) in digest[..16].chunks_exact(4).enumerate() {
        key[w * 4..w * 4 + 4].copy_from_slice(&[chunk[3], chunk[2], chunk[1], chunk[0]]);
    }
    key
}

fn rar4_schedule_short(raw: &[u8]) -> Rar4Keys {
    let mut sha1 = Sha1::new();
    let mut iv = [0u8; 16];
    for i in 0..RAR4_ROUNDS {
        sha1.update(raw);
        sha1.update([
            (i & 0xff) as u8,
            ((i >> 8) & 0xff) as u8,
            ((i >> 16) & 0xff) as u8,
        ]);
        // Every 16th of the rounds contributes one IV byte: the last byte
        // of the digest the chain has reached at that point.
        if i.is_multiple_of(RAR4_ROUNDS / 16) {
            iv[(i / (RAR4_ROUNDS / 16)) as usize] = sha1.clone().finalize()[19];
        }
    }
    Rar4Keys {
        key: rar4_key_from_digest(&sha1.finalize()),
        iv,
    }
}

/// The full schedule, including RAR3's in-place mutation of the password
/// buffer for every complete SHA-1 block the repeated input crosses.
fn rar4_schedule_long(raw: &mut Vec<u8>) -> Rar4Keys {
    let raw_size = raw.len();
    raw.resize(raw_size + 64, 0);
    let mut sha1 = Sha1::new();
    let mut iv = [0u8; 16];
    let mut pos = 0u32;
    for i in 0..RAR4_ROUNDS {
        sha1.update(&raw[..raw_size]);
        let end_pos = (pos + raw_size as u32) & !(64 - 1);
        if end_pos > pos + 64 {
            let mut cur = (pos & !(64 - 1)) + 64;
            while cur != end_pos {
                let off = (cur - pos) as usize;
                rar4_mutate_block(&mut raw[off..off + 64]);
                cur += 64;
            }
        }
        pos = pos.wrapping_add(raw_size as u32);
        sha1.update([
            (i & 0xff) as u8,
            ((i >> 8) & 0xff) as u8,
            ((i >> 16) & 0xff) as u8,
        ]);
        pos = pos.wrapping_add(3);
        if i.is_multiple_of(RAR4_ROUNDS / 16) {
            iv[(i / (RAR4_ROUNDS / 16)) as usize] = sha1.clone().finalize()[19];
        }
    }
    Rar4Keys {
        key: rar4_key_from_digest(&sha1.finalize()),
        iv,
    }
}

/// One 64-byte block of RAR3's password-buffer mutation: expand it as a
/// SHA-1 message schedule and write words 64..80 back over its first 64
/// bytes, little-endian.
fn rar4_mutate_block(data: &mut [u8]) {
    let mut w = [0u32; 80];
    for (i, chunk) in data.chunks_exact(4).take(16).enumerate() {
        w[i] = u32::from_be_bytes(chunk.try_into().expect("SHA-1 word size"));
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }
    for (i, word) in w[64..80].iter().enumerate() {
        data[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
}

/// The 12-byte stored check = 8-byte value + first 4 bytes of its
/// SHA-256. Only a csum-valid stored check can veto a password: a
/// corrupted check value must not condemn a correct password (unrar
/// behaves the same way).
pub fn check_rejects_password(keys: &Rar5Keys, stored: &[u8; 12]) -> bool {
    check_rejects(&keys.psw_check, stored)
}

/// [`check_rejects_password`] against a bare check value - the form
/// [`EntryKeys`] carries, so the format-agnostic paths need not rebuild a
/// whole [`Rar5Keys`] to ask.
pub fn check_rejects(psw_check: &[u8; 8], stored: &[u8; 12]) -> bool {
    check_is_wellformed(stored) && &stored[..8] != psw_check
}

/// The "tweaked checksum" fold (crypt-record flag 0x02): WinRAR stores
/// HMAC-SHA256(hash_key, LE(crc32)) XOR-folded to 4 bytes instead of the
/// bare CRC32, so a stored checksum reveals nothing about the plaintext
/// to someone without the password. Matches `mac_crc32` in the vendored
/// rars fork (crypto/rar50.rs) and unrar's `ConvertHashToMAC`.
///
/// Comparing a computed plaintext CRC32 through this fold is strictly
/// STRONGER than the 8-byte password check: it proves the key AND that
/// every plaintext byte matches what the poster packed. That makes it a
/// usable password gate for a set whose crypt record carries no
/// (well-formed) check value at all - see [`Rar5Keys::hash_key`].
pub fn mac_crc32_with_key(hash_key: &[u8; 32], crc: u32) -> u32 {
    let mut mac =
        <HmacSha256 as MacKeyInit>::new_from_slice(hash_key).expect("HMAC accepts any key length");
    mac.update(&crc.to_le_bytes());
    let digest = mac.finalize().into_bytes();
    digest.chunks_exact(4).fold(0u32, |acc, c| {
        acc ^ u32::from_le_bytes(c.try_into().unwrap())
    })
}

/// [`mac_crc32_with_key`] against a derived key set.
pub fn mac_crc32(keys: &Rar5Keys, crc: u32) -> u32 {
    mac_crc32_with_key(&keys.hash_key, crc)
}

/// Does the stored check value carry a valid self-csum, i.e. can it decide
/// anything at all about a password?
///
/// Callers must not read "did not reject" as "verified": a check whose csum is
/// wrong rejects NOTHING, for every password. Such a value is exactly as
/// useless as no check at all, and an entry carrying one has to take the
/// same conservative route (hand it to a tool that validates the password
/// itself) rather than the native-decrypt-with-a-verified-password route.
pub fn check_is_wellformed(stored: &[u8; 12]) -> bool {
    let csum = Sha256::digest(&stored[..8]);
    stored[8..12] == csum[..4]
}

/// Streaming AES-CBC decryptor (256-bit for RAR5, 128-bit for RAR4).
/// `data` length must be a multiple of 16; chaining state carries across
/// calls, so a multi-gigabyte file decrypts in bounded chunks.
pub struct CbcStream {
    dec: CbcDec,
}

enum CbcDec {
    A256(Aes256CbcDec),
    A128(Aes128CbcDec),
}

impl CbcStream {
    pub fn new(key: &AesKey, iv: &[u8; 16]) -> CbcStream {
        CbcStream {
            dec: match key {
                AesKey::Aes256(k) => CbcDec::A256(Aes256CbcDec::new(k.into(), iv.into())),
                AesKey::Aes128(k) => CbcDec::A128(Aes128CbcDec::new(k.into(), iv.into())),
            },
        }
    }

    /// Decrypt `data` in place (len % 16 == 0).
    pub fn decrypt(&mut self, data: &mut [u8]) {
        match &mut self.dec {
            CbcDec::A256(d) => d.decrypt_blocks(as_blocks(data)),
            CbcDec::A128(d) => d.decrypt_blocks(as_blocks(data)),
        }
    }
}

/// One-shot decrypt of an aligned buffer (header blocks).
pub fn cbc_decrypt(key: &AesKey, iv: &[u8; 16], data: &mut [u8]) {
    CbcStream::new(key, iv).decrypt(data);
}

/// Encrypt helper - the test-fixture writers build real encrypted
/// archives with it (streaming, chaining across calls like CbcStream).
#[doc(hidden)]
pub struct CbcEncStream {
    enc: CbcEnc,
}

enum CbcEnc {
    A256(Aes256CbcEnc),
    A128(Aes128CbcEnc),
}

#[doc(hidden)]
impl CbcEncStream {
    pub fn new(key: &AesKey, iv: &[u8; 16]) -> CbcEncStream {
        CbcEncStream {
            enc: match key {
                AesKey::Aes256(k) => CbcEnc::A256(Aes256CbcEnc::new(k.into(), iv.into())),
                AesKey::Aes128(k) => CbcEnc::A128(Aes128CbcEnc::new(k.into(), iv.into())),
            },
        }
    }

    pub fn encrypt(&mut self, data: &mut [u8]) {
        match &mut self.enc {
            CbcEnc::A256(e) => e.encrypt_blocks(as_blocks(data)),
            CbcEnc::A128(e) => e.encrypt_blocks(as_blocks(data)),
        }
    }
}

/// Build the stored 12-byte check value for a key set (fixture writers).
#[doc(hidden)]
pub fn make_check(keys: &Rar5Keys) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[..8].copy_from_slice(&keys.psw_check);
    let csum = Sha256::digest(keys.psw_check);
    out[8..].copy_from_slice(&csum[..4]);
    out
}

/// Round a byte count up to the AES block size.
pub fn align16(n: u64) -> u64 {
    (n + 15) & !15
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-answer test against real `rar 7.23` output: salt and stored
    /// password-check captured from a `-m0 -ptestpw123` archive's file
    /// crypto record (lg2 count 15). The committed `testdata/rar5/`
    /// fixtures exercise the same path through the full parser.
    #[test]
    fn kdf_matches_real_rar_check_values() {
        let salt: [u8; 16] = [
            0x9b, 0xcb, 0x5d, 0x14, 0x2e, 0x58, 0x5c, 0x72, 0xa8, 0xcd, 0x18, 0x11, 0x5f, 0x1c,
            0x61, 0x09,
        ];
        let keys = derive_keys("testpw123", &salt, 15).unwrap();
        assert_eq!(
            keys.psw_check,
            [0x54, 0x1b, 0x2d, 0xd4, 0x84, 0xea, 0xc7, 0x7d],
            "PBKDF2 chain diverges from real rar output"
        );
        // The stored 12-byte check from the same archive must NOT reject.
        let stored: [u8; 12] = [
            0x54, 0x1b, 0x2d, 0xd4, 0x84, 0xea, 0xc7, 0x7d, 0x3b, 0x09, 0xf3, 0xc2,
        ];
        assert!(!check_rejects_password(&keys, &stored));
        // …and its csum field really is SHA-256 of the first 8 bytes
        // (otherwise the assertion above passed vacuously).
        let csum = Sha256::digest(&stored[..8]);
        assert_eq!(stored[8..12], csum[..4]);
        // A wrong password must be rejected by the same stored check.
        let wrong = derive_keys("testpw124", &salt, 15).unwrap();
        assert!(check_rejects_password(&wrong, &stored));
        // A corrupted check value (bad csum) must not veto anything.
        let mut bad = stored;
        bad[0] ^= 0xff;
        assert!(!check_rejects_password(&wrong, &bad));
    }

    /// Header-encryption KAT: salt/check captured from a real `-hp`
    /// archive's type-4 (archive encryption) block.
    #[test]
    fn kdf_matches_header_crypt_check() {
        let salt: [u8; 16] = [
            0x15, 0x5c, 0xde, 0x80, 0x9e, 0x10, 0x18, 0x0c, 0xa2, 0xa4, 0x48, 0xcc, 0x58, 0x9c,
            0x70, 0x57,
        ];
        let keys = derive_keys("testpw123", &salt, 15).unwrap();
        assert_eq!(
            keys.psw_check,
            [0xf9, 0x31, 0xa0, 0xd2, 0x5a, 0x07, 0xb5, 0xe4]
        );
    }

    #[test]
    fn cbc_roundtrip_streaming() {
        let key = AesKey::Aes256([7u8; 32]);
        let iv = [3u8; 16];
        let plain: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let mut buf = plain.clone();
        let mut enc = CbcEncStream::new(&key, &iv);
        enc.encrypt(&mut buf);
        assert_ne!(buf, plain);
        // Decrypt in mismatched chunk sizes to prove chaining carries.
        let mut dec = CbcStream::new(&key, &iv);
        let (a, b) = buf.split_at_mut(1024 + 16);
        dec.decrypt(a);
        dec.decrypt(b);
        assert_eq!(buf, plain);
    }

    #[test]
    fn hostile_kdf_count_refused() {
        assert!(derive_keys("x", &[0u8; 16], 25).is_none());
        assert!(derive_keys("x", &[0u8; 16], 255).is_none());
    }

    /// The tweaked-checksum fold must match the vendored rars fork's
    /// `mac_crc32` (vendor/rars/src/crypto/rar50.rs), which is unrar's
    /// `ConvertHashToMAC`: HMAC-SHA256 of the LE CRC under hash_key,
    /// XOR-folded over its four LE u32 chunks. Recomputed here from the
    /// primitive rather than the helper, so a refactor of either side
    /// that drifts is caught.
    #[test]
    fn mac_crc32_matches_the_reference_fold() {
        let keys = derive_keys("pw", &[7u8; 16], 12).unwrap();
        for crc in [0u32, 1, 0xdead_beef, u32::MAX] {
            let mut mac = <HmacSha256 as MacKeyInit>::new_from_slice(&keys.hash_key).unwrap();
            mac.update(&crc.to_le_bytes());
            let d = mac.finalize().into_bytes();
            let want = d
                .chunks_exact(4)
                .fold(0u32, |a, c| a ^ u32::from_le_bytes(c.try_into().unwrap()));
            assert_eq!(mac_crc32(&keys, crc), want, "crc {crc:#x}");
        }
    }

    /// RAR4 KAT, taken from the vendored rars fork's own
    /// `rar30_aes_encrypt_decrypt_round_trips_blocks` (crypto/rar30.rs):
    /// same password, same salt, same plaintext, and the ciphertext it
    /// asserts byte-for-byte. That fork's RAR4 crypto is unrar-validated
    /// (`testdata/rar4/` was written with it and passes `unrar t`), so
    /// matching it proves this port derives the SAME AES-128 key and the
    /// SAME KDF-supplied IV - the two things nothing downstream can check.
    #[test]
    fn rar4_kdf_matches_the_rars_fork_vector() {
        let keys = derive_keys_v4("password", Some([1, 2, 3, 4, 5, 6, 7, 8]));
        let mut data = *b"0123456789abcdefRAR AES CBC data";
        CbcEncStream::new(&AesKey::Aes128(keys.key), &keys.iv).encrypt(&mut data);
        assert_eq!(
            data,
            [
                0x5e, 0x59, 0xce, 0xa1, 0x16, 0xca, 0xa2, 0x1d, 0x4d, 0xc5, 0x05, 0xeb, 0xa9, 0x3f,
                0x7b, 0xcd, 0x0d, 0x04, 0xff, 0xea, 0x60, 0x67, 0x3d, 0xaf, 0x6a, 0x8f, 0x02, 0xb2,
                0x03, 0xc8, 0x7d, 0xde,
            ],
            "RAR4 key schedule diverges from the rars fork"
        );
        let mut back = data;
        cbc_decrypt(&AesKey::Aes128(keys.key), &keys.iv, &mut back);
        assert_eq!(&back, b"0123456789abcdefRAR AES CBC data");
    }

    /// The same fork vector for the LONG-password path, where
    /// UTF-16(password) + salt fills complete SHA-1 blocks and RAR3
    /// mutates its own password buffer as it goes. A port that only
    /// implemented the simple path would pass the test above and silently
    /// produce the wrong key here.
    #[test]
    fn rar4_kdf_matches_the_fork_on_the_password_mutation_path() {
        let pw = "this-password-is-deliberately-long-enough-to-exceed-64-bytes-utf16";
        assert!(
            pw.len() * 2 + 8 >= 64,
            "case must exercise the mutation path"
        );
        let keys = derive_keys_v4(pw, Some(*b"longsalt"));
        let mut data = *b"0123456789abcdefRAR AES CBC data";
        CbcEncStream::new(&AesKey::Aes128(keys.key), &keys.iv).encrypt(&mut data);
        assert_eq!(
            data,
            [
                0xb9, 0xa7, 0xac, 0x4b, 0x81, 0x0a, 0x5c, 0xf1, 0x6e, 0xd4, 0x5a, 0x4c, 0xbc, 0x1e,
                0x2e, 0xef, 0x53, 0x7b, 0x89, 0x63, 0x7a, 0xc5, 0x7a, 0x1e, 0xfc, 0x43, 0x3c, 0x18,
                0xea, 0xfd, 0x54, 0xed,
            ]
        );
    }

    /// The salt is part of the key, so a set whose header omits it (the
    /// legacy no-`FHD_SALT` shape) derives different material - and the
    /// two paths must not collapse into each other.
    #[test]
    fn rar4_salt_changes_the_key_and_the_iv() {
        let unsalted = derive_keys_v4("pw", None);
        let salted = derive_keys_v4("pw", Some([0; 8]));
        assert_ne!(unsalted.key, salted.key);
        assert_ne!(unsalted.iv, salted.iv);
        assert_ne!(salted.key, derive_keys_v4("pw", Some([1; 8])).key);
        assert_ne!(salted.key, derive_keys_v4("px", Some([0; 8])).key);
    }

    /// AES-128 and AES-256 must not be interchangeable behind [`AesKey`]:
    /// a 16-byte key really drives the 128-bit cipher.
    #[test]
    fn aes128_cbc_round_trips_independently_of_aes256() {
        let k128 = AesKey::Aes128([9u8; 16]);
        let iv = [4u8; 16];
        let plain: Vec<u8> = (0..2048u32).map(|i| (i % 253) as u8).collect();
        let mut buf = plain.clone();
        CbcEncStream::new(&k128, &iv).encrypt(&mut buf);
        assert_ne!(buf, plain);
        // Chunked decrypt proves the chaining state carries, like RAR5's.
        let mut dec = CbcStream::new(&k128, &iv);
        let (a, b) = buf.split_at_mut(512 + 16);
        dec.decrypt(a);
        dec.decrypt(b);
        assert_eq!(buf, plain);
    }

    /// Perf gate for the RustCrypto stack (the aes/cbc generation this
    /// crate pins): decrypt 1 GiB of AES-CBC through [`CbcStream`] - the
    /// exact path every encrypted-RAR byte takes - and print MB/s. Run
    /// explicitly, in release, alone (a second test in the process
    /// contends for the same cores):
    ///
    /// ```sh
    /// cargo test -p nzbkit --release --lib -- --ignored --test-threads=1 \
    ///   --exact rarcrypt::tests::aes_cbc_decrypt_throughput --nocapture
    /// ```
    ///
    /// Hardware AES is unmissable here (~230 MB/s soft vs multi-GB/s on
    /// AES-NI/ARMv8, measured 2026-07-21) - a dependency bump that
    /// silently drops the hardware backend fails this by 50x, and a
    /// same-backend regression shows up as a percentage. Not asserted,
    /// by design: boxes vary; the number is for a human gate. This gate
    /// is what kept the aes 0.9/cbc 0.2 convergence out on 2026-08-01
    /// (see deny.toml's bans note for the numbers).
    #[test]
    #[ignore = "perf measurement - run in release with --nocapture"]
    fn aes_cbc_decrypt_throughput() {
        const CHUNK: usize = 64 * 1024 * 1024;
        const PASSES: usize = 16; // 16 x 64 MiB = 1 GiB
        let mut buf = vec![0u8; CHUNK];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
        for (label, key) in [
            ("AES-256-CBC (RAR5)", AesKey::Aes256([0x42; 32])),
            ("AES-128-CBC (RAR4)", AesKey::Aes128([0x42; 16])),
        ] {
            let mut dec = CbcStream::new(&key, &[7u8; 16]);
            let t = std::time::Instant::now();
            for _ in 0..PASSES {
                dec.decrypt(&mut buf);
            }
            let secs = t.elapsed().as_secs_f64();
            let mb = (PASSES * CHUNK) as f64 / 1e6;
            std::hint::black_box(&buf);
            println!(
                "{label} decrypt: {:.0} MB/s ({secs:.3} s for {mb:.0} MB)",
                mb / secs
            );
        }
    }

    /// The fold is keyed: the same CRC under a different password folds
    /// differently, which is what makes it a password gate and not just
    /// an obfuscation.
    #[test]
    fn mac_crc32_is_keyed_by_the_password() {
        let a = derive_keys("right", &[3u8; 16], 12).unwrap();
        let b = derive_keys("wrong", &[3u8; 16], 12).unwrap();
        assert_ne!(mac_crc32(&a, 0x1234_5678), mac_crc32(&b, 0x1234_5678));
    }
}
