use aes::cipher::{consts::U16, inout::InOutBuf, BlockCipherEncrypt, BlockModeDecrypt, KeyInit, KeyIvInit};
use aes::Aes256;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

const MAX_KDF_COUNT_LOG: u8 = 24;
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    KdfCountTooLarge,
    BadPassword,
    UnalignedInput,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KdfCountTooLarge => f.write_str("RAR 5 KDF count is too large"),
            Self::BadPassword => f.write_str("wrong password or corrupt encrypted data"),
            Self::UnalignedInput => f.write_str("RAR 5 AES input is not block aligned"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, ZeroizeOnDrop)]
#[non_exhaustive]
pub struct Rar50Keys {
    pub key: [u8; 32],
    pub hash_key: [u8; 32],
    pub password_check: [u8; 8],
}

impl std::fmt::Debug for Rar50Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rar50Keys").finish_non_exhaustive()
    }
}

impl PartialEq for Rar50Keys {
    fn eq(&self, other: &Self) -> bool {
        let key_eq = constant_time_eq(&self.key, &other.key);
        let hash_eq = constant_time_eq(&self.hash_key, &other.hash_key);
        let check_eq = constant_time_eq(&self.password_check, &other.password_check);
        key_eq & hash_eq & check_eq
    }
}

impl Eq for Rar50Keys {}

impl Rar50Keys {
    pub fn derive(password: &[u8], salt: [u8; 16], kdf_count_log: u8) -> Result<Self> {
        if kdf_count_log > MAX_KDF_COUNT_LOG {
            return Err(Error::KdfCountTooLarge);
        }

        let mut first_input = Vec::with_capacity(salt.len() + 4);
        first_input.extend_from_slice(&salt);
        first_input.extend_from_slice(&1u32.to_be_bytes());

        // Key the HMAC once and clone the pre-keyed state per iteration: the
        // clone carries the already-absorbed ipad/opad key schedule, so the
        // 2^kdf_count_log iterations each cost two SHA-256 blocks instead of
        // re-deriving the key schedule (two extra compressions plus key
        // preparation) every time.
        let hmac_template =
            <HmacSha256 as KeyInit>::new_from_slice(password).expect("HMAC accepts keys of any size");
        let prf = |data: &[u8]| -> [u8; 32] {
            let mut hmac = hmac_template.clone();
            hmac.update(data);
            hmac.finalize().into_bytes().into()
        };

        let mut u = prf(&first_input);
        let mut accumulator = u;
        let mut taps = [[0u8; 32]; 3];
        let mut iterations = (1u32 << kdf_count_log) - 1;

        for tap in &mut taps {
            for _ in 0..iterations {
                u = prf(&u);
                for (acc, byte) in accumulator.iter_mut().zip(u) {
                    *acc ^= byte;
                }
            }
            *tap = accumulator;
            iterations = 16;
        }

        let mut password_check = [0u8; 8];
        for (i, byte) in password_check.iter_mut().enumerate() {
            *byte = taps[2][i] ^ taps[2][i + 8] ^ taps[2][i + 16] ^ taps[2][i + 24];
        }

        let result = Self {
            key: taps[0],
            hash_key: taps[1],
            password_check,
        };
        u.zeroize();
        accumulator.zeroize();
        taps.zeroize();
        Ok(result)
    }

    pub fn check_password(&self, stored: &[u8; 12]) -> Result<()> {
        let checksum = sha256(&stored[..8]);
        let checksum_matches = constant_time_eq(&checksum[..4], &stored[8..12]);
        let password_matches = constant_time_eq(&self.password_check, &stored[..8]);
        if !(checksum_matches & password_matches) {
            return Err(Error::BadPassword);
        }
        Ok(())
    }

    pub fn password_check_record(&self) -> [u8; 12] {
        let mut record = [0u8; 12];
        record[..8].copy_from_slice(&self.password_check);
        record[8..].copy_from_slice(&sha256(&self.password_check)[..4]);
        record
    }

    pub fn mac_crc32(&self, crc: u32) -> u32 {
        let digest = hmac_sha256(&self.hash_key, &crc.to_le_bytes());
        digest.chunks_exact(4).fold(0, |acc, chunk| {
            acc ^ u32::from_le_bytes(chunk.try_into().unwrap())
        })
    }

    pub fn mac_hash32(&self, hash: [u8; 32]) -> [u8; 32] {
        hmac_sha256(&self.hash_key, &hash)
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&left, &right) in left.iter().zip(right) {
        diff |= left ^ right;
    }
    diff == 0
}

#[derive(ZeroizeOnDrop)]
pub struct Rar50Cipher {
    cipher: Aes256,
    /// The decrypt direction, carrying its own chain state across calls.
    /// `cipher` and `iv` serve the encrypt direction (the writer).
    decryptor: cbc::Decryptor<Aes256>,
    iv: [u8; 16],
}

impl Rar50Cipher {
    pub fn new(key: [u8; 32], iv: [u8; 16]) -> Self {
        Self {
            cipher: Aes256::new(&key.into()),
            decryptor: cbc::Decryptor::<Aes256>::new(&key.into(), &iv.into()),
            iv,
        }
    }

    pub fn decrypt_in_place(&mut self, data: &mut [u8]) -> Result<()> {
        if !data.len().is_multiple_of(16) {
            return Err(Error::UnalignedInput);
        }
        // Through `cbc::Decryptor`, in place, eight blocks per backend
        // call. CBC decryption has no chain between blocks (plaintext_i =
        // D(c_i) ^ c_{i-1}), so the mode hands the backend `ParBlocksSize`
        // blocks at once and the AES pipelines overlap. The old one-block
        // loop exposed each 14-round latency chain: on an i5-10600KF it
        // measured 3.15 GB/s against 4.57 for this shape (ECB ceiling
        // 4.67); on Apple silicon both read ~14 GB/s, the core overlapping
        // the chains by itself (research/RAR-PERF-AUDIT-2026-09-02.md,
        // round 2). `InOutBuf::into_chunks` is the safe view of the byte
        // slice as blocks; the tail is empty by the alignment check above.
        let (blocks, _tail) = InOutBuf::from(data).into_chunks::<U16>();
        self.decryptor.decrypt_blocks_inout(blocks);
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
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut hmac =
        <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC accepts keys of any size");
    hmac.update(data);
    hmac.finalize().into_bytes().into()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_standard_vectors() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hmac_sha256_matches_standard_vector() {
        assert_eq!(
            hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn password_check_uses_the_check_value_and_its_checksum() {
        let keys = Rar50Keys::derive(b"secret", [7; 16], 4).unwrap();
        let mut record = keys.password_check_record();

        assert_eq!(keys.check_password(&record), Ok(()));

        record[0] ^= 0x01;
        assert_eq!(keys.check_password(&record), Err(Error::BadPassword));

        let mut record = keys.password_check_record();
        record[11] ^= 0x01;
        assert_eq!(keys.check_password(&record), Err(Error::BadPassword));
    }

    #[test]
    fn rar50_aes_encrypt_decrypt_round_trips_blocks() {
        let key = [9u8; 32];
        let iv = [5u8; 16];
        let mut data = *b"0123456789abcdefRAR5 block two!!";
        let plain = data;

        Rar50Cipher::new(key, iv)
            .encrypt_in_place(&mut data)
            .unwrap();
        assert_ne!(data, plain);

        Rar50Cipher::new(key, iv)
            .decrypt_in_place(&mut data)
            .unwrap();
        assert_eq!(data, plain);
    }

    #[test]
    fn rar50_aes_rejects_partial_tail() {
        let key = [9u8; 32];
        let iv = [5u8; 16];
        let mut data = *b"partial block!!";

        assert_eq!(
            Rar50Cipher::new(key, iv).encrypt_in_place(&mut data),
            Err(Error::UnalignedInput)
        );
        assert_eq!(
            Rar50Cipher::new(key, iv).decrypt_in_place(&mut data),
            Err(Error::UnalignedInput)
        );
    }

    #[test]
    fn rar50_kdf_matches_pinned_vector() {
        let keys = Rar50Keys::derive(
            b"password",
            [
                0x00, 0x01, 0x02, 0x03, 0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x23, 0x30, 0x31,
                0x32, 0x33,
            ],
            4,
        )
        .unwrap();

        assert_eq!(
            hex(&keys.key),
            "cae43ebc57fcbdfc97ddc6f4a2d09687fd06010b51f651bec8f911f20caf008f"
        );
        assert_eq!(
            hex(&keys.hash_key),
            "e65c566ff17139eaabdf60986e64058aac7e8dd82d6c5b027dd2e6d761a44d3c"
        );
        assert_eq!(hex(&keys.password_check), "118929fdcad8a74f");
        assert_eq!(
            hex(&keys.password_check_record()),
            "118929fdcad8a74f5379ff2d"
        );
        assert_eq!(keys.mac_crc32(0x1234_5678), 0xd742_398d);
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
