//! RAR volume header parsing + store-mode extraction mapping (design: M3).
//!
//! The one-pass trick: for store-mode (uncompressed) RAR sets - the norm
//! for large scene posts - a volume is just headers wrapped around
//! verbatim slices of the inner files. Parsing only the headers yields a
//! (volume, offset) → (inner file, offset) map, so decoded articles can
//! `pwrite` straight into the *extracted* file and the volumes never
//! touch disk.
//!
//! Both wire formats are supported:
//! - RAR5 (`Rar!\x1a\x07\x01\x00`): vint-encoded blocks, CRC32 header
//!   checksums, split flags 0x08/0x10, method in compression_info bits
//!   7–9 (0 = store), encryption as block type 4 (encrypted headers) or a
//!   file-extra record (encrypted data).
//! - RAR4 (`Rar!\x1a\x07\x00`): fixed little-endian headers, method byte
//!   0x30 = store, split flags 0x01/0x02, MHD_PASSWORD/LHD_PASSWORD.
//!
//! [`VolumeMapper`] parses incrementally from out-of-order article spans:
//! it keeps a small window at the parse cursor (headers are tiny; data
//! areas are skipped arithmetically), so mapping a volume needs only the
//! bytes at its header positions - usually all inside article 1 for
//! single-file volumes.

use std::collections::{HashMap, HashSet};

use crate::rarcrypt;

/// Compression method of an entry piece.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Store,
    Compressed,
}

/// RAR5 file-encryption parameters (extra record 0x01). A multi-volume
/// set encrypts each inner file as ONE continuous AES-256-CBC stream and
/// repeats the SAME record (salt, IV, check) in every volume's file
/// header - piece boundaries are arbitrary byte offsets, only the very
/// end is padded to 16 (total ciphertext = align16(unpacked_size)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rar5Crypt {
    /// PBKDF2 iteration count exponent (iterations = 2^lg2_count).
    pub lg2_count: u8,
    pub salt: [u8; 16],
    pub iv: [u8; 16],
    /// Stored password check (8-byte value + 4-byte SHA-256 csum), when
    /// the archiver wrote one (WinRAR does by default).
    pub check: Option<[u8; 12]>,
    /// Crypt flag 0x02: the file CRC in the header is TWEAKED (mixed with
    /// the hash key so it can't fingerprint the plaintext). It is still
    /// checkable - fold the computed CRC the same way before comparing
    /// (`rarcrypt::mac_crc32`) - just not against a bare CRC32.
    pub tweaked_checksum: bool,
}

/// RAR4 file-encryption parameters. The whole record is one optional
/// 8-byte salt (file flag `FHD_SALT`, stored after the name): the AES-128
/// key AND the CBC IV both come out of the SHA-1 key schedule, and the
/// format stores no password check and no checksum tweak at all.
///
/// The stream shape matches RAR5's exactly - one continuous CBC stream per
/// inner file across every volume, the same salt repeated in each volume's
/// header, padded to 16 only at the very end - which is what lets the
/// store mapper treat both the same way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rar4Crypt {
    pub salt: Option<[u8; 8]>,
}

/// Decryption parameters for one encrypted entry, in whichever format the
/// archive uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryCrypt {
    Rar5(Rar5Crypt),
    Rar4(Rar4Crypt),
}

impl EntryCrypt {
    /// The RAR5 record, for the paths that genuinely need RAR5-shaped
    /// parameters (the candidate probe, the resume journal's `E` line).
    pub fn rar5(&self) -> Option<&Rar5Crypt> {
        match self {
            EntryCrypt::Rar5(c) => Some(c),
            EntryCrypt::Rar4(_) => None,
        }
    }

    /// Derive this entry's key material from `password`. `None` only for a
    /// hostile RAR5 iteration count; RAR4's round count is fixed by the
    /// format, so it cannot be attacked this way.
    pub fn derive(&self, password: &str) -> Option<rarcrypt::EntryKeys> {
        match self {
            EntryCrypt::Rar5(c) => {
                let k = rarcrypt::derive_keys(password, &c.salt, c.lg2_count)?;
                Some(rarcrypt::EntryKeys {
                    aes: rarcrypt::AesKey::Aes256(k.key),
                    iv: c.iv,
                    hash_key: Some(k.hash_key),
                    psw_check: Some(k.psw_check),
                })
            }
            EntryCrypt::Rar4(c) => {
                let k = rarcrypt::derive_keys_v4(password, c.salt);
                Some(rarcrypt::EntryKeys {
                    aes: rarcrypt::AesKey::Aes128(k.key),
                    iv: k.iv,
                    hash_key: None,
                    psw_check: None,
                })
            }
        }
    }

    /// Is this entry's stored checksum the keyed fold of the plaintext
    /// CRC32 rather than the CRC32 itself? Only RAR5 has the flag; a RAR4
    /// header always stores the bare plaintext CRC32.
    pub fn tweaked_checksum(&self) -> bool {
        matches!(self, EntryCrypt::Rar5(c) if c.tweaked_checksum)
    }

    /// Does this entry's stored check actually VERIFY `keys`, as opposed
    /// to merely failing to veto them? Only a present, csum-valid check
    /// can: a malformed one rejects nothing for any password, so reading
    /// "did not reject" as "verified" would wave a wrong password
    /// through (see `entry_blocker`).
    ///
    /// Always false for RAR4, which stores no check value of any kind.
    ///
    /// False does NOT mean the password is wrong - it means nothing here
    /// can vouch for it before the data is decrypted, so the caller must
    /// keep a recoverable route: assemble ciphertext rather than
    /// decrypting in place, and require a whole-file checksum to pass
    /// before publishing.
    pub fn check_verifies(&self, keys: &rarcrypt::EntryKeys) -> bool {
        let EntryCrypt::Rar5(c) = self else {
            return false;
        };
        let Some(psw_check) = keys.psw_check else {
            return false;
        };
        c.check.as_ref().is_some_and(|chk| {
            rarcrypt::check_is_wellformed(chk) && !rarcrypt::check_rejects(&psw_check, chk)
        })
    }
}

/// One file piece described by a volume's headers.
#[derive(Debug, Clone)]
pub struct FileEntry {
    pub name: String,
    /// Total unpacked size of the inner file (repeated in every volume).
    pub unpacked_size: u64,
    pub method: Method,
    pub encrypted: bool,
    /// Decryption parameters for an encrypted entry (RAR5 only; a RAR4
    /// encrypted entry has `encrypted` set and no params).
    pub crypt: Option<EntryCrypt>,
    /// Stored whole-file CRC32 of the unpacked data (RAR5 file flag
    /// 0x04, or the RAR4 file-header CRC). For an encrypted entry it
    /// verifies the decrypted output - but only when the crypt record's
    /// tweaked-checksum flag is clear.
    pub file_crc: Option<u32>,
    /// Stored RAR5 file-hash extra record (FHEXTRA_HASH, type 0x02):
    /// `(hash_type, digest)`. hash_type 0 is BLAKE2sp (32-byte digest);
    /// carried so a CRC-less entry is not silently treated as verified.
    pub hash: Option<(u64, Vec<u8>)>,
    pub is_dir: bool,
    /// RAR5 "unpacked size unknown" file flag (0x08): `unpacked_size` is
    /// a placeholder, not a real length - nothing may derive offsets
    /// from it.
    pub size_unknown: bool,
    /// Piece continues from the previous volume.
    pub split_before: bool,
    /// Piece continues into the next volume.
    pub split_after: bool,
    /// Offset of this piece's data area within the volume file.
    pub data_off: u64,
    /// Length of this piece's data area.
    pub data_len: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RarVersion {
    V4,
    V5,
}

/// Why a volume can't be (or stopped being) mapped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MapBlocker {
    /// Not a RAR file at all.
    NotRar,
    /// Headers are password-encrypted and no password is available -
    /// nothing can be parsed.
    EncryptedHeaders,
    /// Structure parsed but a piece is compressed, or encrypted without a
    /// usable password; direct extraction is off, volumes must be
    /// materialized.
    NotStore,
    /// Entries are data-encrypted (`rar -p`, plain headers) and NO password
    /// is available at all. Store-shaped, but nothing here or in unrar can
    /// unpack it without a key. Distinct from [`Self::NotStore`] so the
    /// finish ladder keeps the verified volumes and prompts for a password
    /// (like [`Self::EncryptedHeaders`]) instead of running an unrar
    /// attempt that cannot succeed and failing the job.
    EncryptedNoPassword,
    /// The supplied password fails the archive's stored check value.
    BadPassword,
    /// Malformed header (CRC/structure): abort mapping, materialize.
    Corrupt(&'static str),
}

enum ParseState {
    /// Waiting for the signature at `archive_base` (offset 0 for a bare
    /// volume, the stub's length for an SFX).
    Signature,
    /// Next block header expected at `cursor`.
    Blocks,
    /// Reached end of archive (or unrecoverable blocker).
    Done,
}

/// Incremental single-volume header parser. Feed it decoded spans in any
/// order; it consumes bytes at the parse cursor and skips data areas.
pub struct VolumeMapper {
    pub version: Option<RarVersion>,
    pub entries: Vec<FileEntry>,
    pub blocker: Option<MapBlocker>,
    /// RAR5 main-header volume number (0-based; absent on the first
    /// volume and in RAR4) - the obfuscation-proof volume ordering.
    pub volume_number: Option<u64>,
    /// True once the end-of-archive block (or EOF at `volume_size`) is
    /// reached - `entries` is then complete.
    pub complete: bool,
    /// Declared size of the volume file (yEnc total), for EOF detection.
    volume_size: u64,
    /// Where the archive begins inside the file. 0 for every bare
    /// volume; a self-extractor's launcher-stub length (TODO 94 C),
    /// found by `sfx::sfx_payload_at` before this mapper is built. Every
    /// offset this mapper speaks - cursor, entries, `map_span`,
    /// `mapped_through` - stays in FILE coordinates, so the header stash
    /// keeps the stub exactly as it keeps any other non-data bytes and a
    /// demote materializes the posted `.exe` byte for byte.
    archive_base: u64,
    state: ParseState,
    cursor: u64,
    /// Contiguous window starting at `win_base` (== cursor when blocked).
    win_base: u64,
    win: Vec<u8>,
    /// Index in `win` of logical offset 0 (i.e. of `win_base`). A header
    /// advance moves this instead of memmoving the window down, which is
    /// what `rebase` used to do on EVERY parsed member header; the dead
    /// prefix is folded away only when a stash would otherwise push the
    /// buffer past `MAX_WIN` (see `compact`). Round 26 of
    /// research/RAR-PERF-AUDIT-2026-09-02.md measured the old drain at
    /// 71 self samples on the many-member shape, under the routing lock.
    win_off: usize,
    /// Filled intervals in LOGICAL coordinates (relative to `win_base`,
    /// not to the buffer start), so `rebase` shifts them in place.
    filled: Vec<(usize, usize)>,
    /// Archive password, when the job has one - unlocks RAR5 encrypted
    /// headers (type-4 block) and encrypted store-mode entries.
    password: Option<std::sync::Arc<str>>,
    /// Header-decryption keys, derived once the type-4 block parses with
    /// a check-passing password. Every subsequent block is then stored as
    /// a 16-byte IV + AES-256-CBC ciphertext.
    hdr_keys: Option<rarcrypt::Rar5Keys>,
    /// RAR4 `-hp`: the main header carried MHD_PASSWORD, so every block
    /// after it is `8-byte salt + AES-128-CBC ciphertext`. (RAR5 keeps its
    /// derived keys in `hdr_keys` instead; RAR4 re-reads a salt per block,
    /// so only the flag is state.)
    v4_hdr_enc: bool,
    /// First RAR5 crypt record seen (header-encryption type-4 block or an
    /// encrypted file entry), captured EVEN when no password is set so a
    /// candidate can be checked against the archive without a full mapping
    /// pass. A multi-volume set repeats one record in every volume, so the
    /// first is representative. Populated regardless of blocker.
    crypt_seen: Option<CryptProbe>,
}

/// RAR5 crypt parameters harvested from an archive head - enough to test
/// a candidate password against the stored check WITHOUT decrypting any
/// data. `check` is `None` for check-less sets (WinRAR writes one by
/// default; without it a wrong password can only be caught by a real
/// extraction attempt, so those are not probeable here).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptProbe {
    pub lg2_count: u8,
    pub salt: [u8; 16],
    pub check: Option<[u8; 12]>,
}

/// Verdict of testing one candidate against a [`CryptProbe`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PwVerdict {
    /// Passes a valid stored check - the correct password, no decrypt.
    Verified,
    /// Rejected by a valid stored check - definitely wrong.
    Rejected,
    /// No stored check (or a hostile KDF count): can't decide pre-decrypt.
    Indeterminate,
}

impl VolumeMapper {
    /// The archive's RAR5 crypt parameters as far as this mapper has
    /// seen them: the type-4 header-encryption block if one parsed, else
    /// the record riding the first encrypted file entry. `None` when
    /// nothing testable has been seen (plain set, RAR4 encryption).
    /// The live-extraction candidate probe (Increment A) keys off this -
    /// unlike [`crypt_probe`] it needs no file, only the spans already
    /// fed.
    pub fn crypt_probe_params(&self) -> Option<CryptProbe> {
        if let Some(p) = self.crypt_seen.clone() {
            return Some(p);
        }
        self.entries.iter().find_map(|e| {
            e.crypt
                .as_ref()
                .and_then(EntryCrypt::rar5)
                .map(|c| CryptProbe {
                    lg2_count: c.lg2_count,
                    salt: c.salt,
                    check: c.check,
                })
        })
    }
}

impl CryptProbe {
    /// Test `candidate` against the stored check. `Verified`/`Rejected`
    /// are definitive; `Indeterminate` means the caller must fall through
    /// to a real extraction attempt to know (check-less set).
    pub fn verify(&self, candidate: &str) -> PwVerdict {
        let Some(keys) = rarcrypt::derive_keys(candidate, &self.salt, self.lg2_count) else {
            return PwVerdict::Indeterminate;
        };
        match &self.check {
            Some(chk) if rarcrypt::check_rejects_password(&keys, chk) => PwVerdict::Rejected,
            // A check whose own csum is invalid rejects nothing, for ANY
            // password, so it cannot be read as confirmation - that turned the
            // first candidate tried into a false Verified and let a wrong
            // password native-decrypt garbage. It is no more informative than
            // a check-less set, which is exactly what Indeterminate means.
            Some(chk) if !rarcrypt::check_is_wellformed(chk) => PwVerdict::Indeterminate,
            Some(_) => PwVerdict::Verified,
            None => PwVerdict::Indeterminate,
        }
    }
}

/// Read `path`'s head and harvest RAR5 crypt parameters for password
/// testing, or `None` when the archive carries no testable RAR5
/// encryption (a plain/compressed set, RAR4 encryption - no RAR5 params,
/// or an unreadable file). Feeds the head through the header parser with
/// no password: a header-encryption type-4 block is captured before the
/// parser blocks, and file-encrypted sets expose the record on the first
/// encrypted entry.
pub fn crypt_probe(path: &std::path::Path) -> Option<CryptProbe> {
    let mut f = std::fs::File::open(path).ok()?;
    let size = f.metadata().map(|m| m.len()).unwrap_or(0);
    let mut m = VolumeMapper::new(size);
    feed_headers_incrementally(&mut f, size, &mut m);
    if let Some(p) = m.crypt_seen.clone() {
        return Some(p);
    }
    // File-encrypted set with readable headers: the record rides the
    // first encrypted entry.
    m.entries.iter().find_map(|e| {
        e.crypt
            .as_ref()
            .and_then(EntryCrypt::rar5)
            .map(|c| CryptProbe {
                lg2_count: c.lg2_count,
                salt: c.salt,
                check: c.check,
            })
    })
}

/// Does this on-disk volume PROVE that every entry it holds is STORED?
///
/// The disk twin of the in-stream `Inner::saw_store && !saw_compressed`
/// latch, and it exists because the nested depth cap is enforced at TWO
/// independent sites. The stream side learns an entry's `Method` from
/// this same mapper as the articles arrive; the disk post-pass walks
/// files that are already on disk and had no such evidence at all, so a
/// resumed or disk-only job charged a stored layer against a cap that
/// exists to bound DECOMPRESSION - see `nested_cap_after_store_layer`.
///
/// POSITIVE EVIDENCE ONLY, the same direction and for the same reason:
/// the failure mode of getting this backwards is a bomb guard that does
/// not guard. Every one of these is a `false`, and the caller must treat
/// `false` as "unknown", never as "compressed":
///   * anything that is not a readable RAR volume (a zip, a 7z, a tar, a
///     `.rar` whose signature was destroyed, an unreadable file);
///   * any blocker at all - a compressed entry sets `MapBlocker::NotStore`
///     and stops the walk, and so do encrypted headers, a bad password
///     and a corrupt block;
///   * an encrypted entry, whose plaintext this parser never sees;
///   * a mapping that did not COMPLETE, because entries past the point it
///     stopped are entries nobody has looked at;
///   * a volume with no non-directory entry to judge.
///
/// It reads HEADERS, not data: the walk seeks past each member's data
/// area, so a healthy single-entry store volume costs about two reads
/// whatever its size, and the walk is bounded on hostile input. The
/// caller pays this once per archive per nested level, immediately
/// before extracting those same archives in full.
///
/// Deliberately NOT `classify_rar_head`, which reads a 512 KiB prefix and
/// judges `entries.first()` alone. That is enough for the prevalence
/// tally it feeds and is not enough to grant an exemption: a volume
/// whose first entry stores would read as store-only there whatever
/// followed it. What actually catches that here is the BLOCKER, not the
/// loop below - the mapper refuses a compressed entry with
/// `MapBlocker::NotStore` and stops, so the volume never reaches
/// `complete` and the walk stops with it. An exemption granted on absent
/// evidence is the guard that does not guard.
pub fn volume_is_store_only(path: &std::path::Path) -> bool {
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let Ok(size) = f.metadata().map(|m| m.len()) else {
        return false;
    };
    let mut m = VolumeMapper::new(size);
    feed_headers_incrementally(&mut f, size, &mut m);
    // `complete` is the load-bearing one and it subsumes the other two
    // today: the mapper is built with NO password, so a crypt record or
    // an encrypted entry raises a blocker, and every blocker stops the
    // parse short of the end. They are spelled out anyway because the
    // question each answers is different, and a future mapper that
    // learned to finish a volume it could not fully read would make the
    // difference matter. Nothing here is a second guard on the same
    // fact for a caller to lean on - `complete` is.
    if m.blocker.is_some() || !m.complete || m.crypt_seen.is_some() {
        return false;
    }
    let mut saw = false;
    for e in &m.entries {
        if e.encrypted || e.crypt.is_some() {
            return false;
        }
        if e.is_dir {
            // A directory entry carries no data and no method worth
            // reading, exactly as the in-stream latch treats it.
            continue;
        }
        if e.method != Method::Store {
            return false;
        }
        saw = true;
    }
    saw
}

/// Feed a mapper the HEADER regions of `f` incrementally, seeking PAST each
/// member's data area (the parser advances its cursor over member payload
/// without needing those bytes). Unlike a single fixed-size prefix read,
/// this reaches a header that sits after a large plaintext member - e.g. an
/// encrypted second entry behind a >512 KiB plaintext first entry, which a
/// 512 KiB prefix probe missed (finding 17). Stops as soon as enough is
/// known (complete / blocked / a crypt record or encrypted entry seen), at
/// EOF, or after a bounded number of reads on hostile input.
/// Diagnostic wrapper over [`feed_headers_incrementally`] for the
/// `rarprobe` example - maps an on-disk volume's headers.
#[doc(hidden)]
pub fn feed_headers_incrementally_pub(f: &mut std::fs::File, size: u64, m: &mut VolumeMapper) {
    feed_headers_incrementally(f, size, m);
}

/// Fuzz entry point for the RAR4 `-hp` header framing, with the key
/// schedule already run (see `parse_block_v4_enc_with`). Returns
/// `(advanced_to, blocked)` rather than the private `BlockResult`:
/// `advanced_to` is where the parser would put the cursor, which is the
/// value every bound in the mapper is derived from.
#[doc(hidden)]
pub fn fuzz_v4_encrypted_header(
    bytes: &[u8],
    base: u64,
    key: [u8; 16],
    iv: [u8; 16],
    volume_size: u64,
) -> (Option<u64>, bool) {
    let keys = rarcrypt::Rar4Keys { key, iv };
    match parse_block_v4_enc_with(bytes, base, &keys, volume_size) {
        BlockResult::Skip { next, .. } => (Some(next), false),
        BlockResult::File { next, .. } => (Some(next), false),
        BlockResult::V4EncryptedHeaders { next } => (Some(next), false),
        BlockResult::Crypt { next, .. } => (Some(next), false),
        BlockResult::End | BlockResult::NeedMore => (None, false),
        BlockResult::Corrupt(_) | BlockResult::BadPassword | BlockResult::EncryptedHeaders => {
            (None, true)
        }
    }
}

/// Fuzz entry point for the RAR4 PLAINTEXT header framing, past the
/// header CRC16 - the same split, for the same reason, as
/// [`fuzz_v4_encrypted_header`] is past the key schedule.
///
/// Since the M5 fix a plaintext block is refused unless its stored CRC16
/// matches, and random bytes clear that one time in 65,536. Driving only
/// the mapper would therefore leave every length and offset BEHIND the
/// gate - `hsize`, `add_size`, the 64-bit high halves, the packed-name
/// decoder - effectively unfuzzed, which is precisely the arithmetic
/// that turns into `pwrite` destinations. The CRC is a fixed
/// `crc32fast::hash` over a slice and is not what needs execs; the
/// fields it protects are.
///
/// Returns `(advanced_to, blocked)` rather than the private
/// `BlockResult`, matching the encrypted entry point.
#[doc(hidden)]
pub fn fuzz_v4_plain_header(bytes: &[u8], base: u64) -> (Option<u64>, bool) {
    // `Some(hsize)` would be a lie about the span; feed the real
    // plaintext shape and let the parser derive it, minus only the CRC
    // check that `hdr_span.is_none()` would otherwise run.
    if bytes.len() < 7 {
        return (None, false);
    }
    let hsize = rd_u16(&bytes[5..]) as u64;
    match parse_block_v4_at(bytes, base, Some(hsize)) {
        BlockResult::Skip { next, .. } => (Some(next), false),
        BlockResult::File { next, .. } => (Some(next), false),
        BlockResult::V4EncryptedHeaders { next } => (Some(next), false),
        BlockResult::Crypt { next, .. } => (Some(next), false),
        BlockResult::End | BlockResult::NeedMore => (None, false),
        BlockResult::Corrupt(_) | BlockResult::BadPassword | BlockResult::EncryptedHeaders => {
            (None, true)
        }
    }
}

fn feed_headers_incrementally(f: &mut std::fs::File, size: u64, m: &mut VolumeMapper) {
    use std::io::{Read, Seek, SeekFrom};
    const CHUNK: usize = 64 * 1024;
    const MAX_READS: usize = 1024;
    let mut buf = vec![0u8; CHUNK];
    let mut fed_upto = 0u64; // file offset one past the last byte fed
    for _ in 0..MAX_READS {
        if m.complete
            || m.blocker.is_some()
            || m.crypt_seen.is_some()
            || m.entries.iter().any(|e| e.crypt.is_some() || e.encrypted)
        {
            return;
        }
        // Read at the parse cursor (skips a member's data) or, when a header
        // straddles the last chunk, the next contiguous bytes.
        let want = m.cursor.max(fed_upto);
        if want >= size {
            return;
        }
        if f.seek(SeekFrom::Start(want)).is_err() {
            return;
        }
        let mut n = 0;
        while n < buf.len() {
            match f.read(&mut buf[n..]) {
                Ok(0) => break,
                Ok(k) => n += k,
                Err(_) => return,
            }
        }
        if n == 0 {
            return;
        }
        m.feed(want, &buf[..n]);
        fed_upto = want + n as u64;
    }
}

/// Headers are small; 4 MiB tolerates huge file-name tables and keeps the
/// window bounded even on hostile input.
const MAX_WIN: usize = 4 << 20;

/// Cap on the entries retained for one volume. The list is held for the
/// whole job and charged to no budget, so a stream of back-to-back file
/// headers (32 bytes each in RAR4, and none of them CRC-checked) grows it
/// at line rate. A real multi-file RAR carries tens of members, not
/// thousands, so this only ever fires on hostile input.
const MAX_ENTRIES: usize = 100_000;

const SIG5: &[u8; 8] = b"Rar!\x1a\x07\x01\x00";
const SIG4: &[u8; 7] = b"Rar!\x1a\x07\x00";

/// RAR4 block type of the main archive header, and RAR5's. An archive
/// opens with one; nothing else may stand in for it here.
const V4_TYPE_MAIN: u8 = 0x73;
const V5_TYPE_MAIN: u64 = 1;

/// Cap on a RAR5 main header's declared size before its bytes are hashed.
/// A real one is tens of bytes - the block intro, the archive flags, and
/// at most a locator record - so 64 KiB is generous slack, and it bounds
/// what one crafted size vint can make a caller checksum.
const V5_MAIN_HEADER_MAX: u64 = 64 << 10;

/// Which RAR dialect's signature `bytes` opens with - 4 or 5.
///
/// The signature ALONE, deliberately: this is for a caller that has
/// already established a real archive starts here (with
/// [`archive_starts_here`], which is the check that makes a magic number
/// evidence) and now only needs to name the dialect for a badge or a log
/// line. The two signatures share their first six bytes and differ at the
/// seventh, so neither is a prefix of the other and the order below is
/// free.
pub fn signature_version(bytes: &[u8]) -> Option<u8> {
    if bytes.starts_with(SIG5) {
        Some(5)
    } else if bytes.starts_with(SIG4) {
        Some(4)
    } else {
        None
    }
}

/// Does a real RAR archive begin at byte 0 of `bytes` - the signature AND
/// a CRC-valid main header behind it?
///
/// Written for callers that found the signature by SEARCHING rather than
/// by opening a file at offset 0, where "these seven bytes appear here" is
/// not evidence: `Rar!\x1a\x07\x00` and the 7z magic occur as constants
/// inside ordinary programs, so a self-extractor gate built on a substring
/// match claims them. Measured over 1,105 real binaries on one Mac (128 of
/// them Windows executables), a bare substring search claims 25, including
/// binaries this project itself ships - every one of them a magic constant
/// in the program's own code, with no archive behind it (TODO 159 item 7).
///
/// The header CRC is what makes the answer evidence rather than a guess:
/// 16 bits of it in RAR4, 32 in RAR5, on top of a block type that has to
/// be MAIN and a declared size that has to be plausible. Both dialects
/// checksum their own headers and this reuses those checks unchanged.
///
/// Deliberately NOT a "can this be extracted" test - it reads one header
/// and stops. A truncated buffer answers false, so a caller scanning a
/// bounded window must keep enough bytes past its candidates for a whole
/// main header to fit.
pub fn archive_starts_here(bytes: &[u8]) -> bool {
    if let Some(a) = bytes.strip_prefix(SIG5) {
        // crc32 u32, header-size vint, then that many bytes of header
        // whose FIRST vint is the block type. The CRC covers the size
        // vint and the header data both - `parse_block_v5`'s rule.
        if a.len() < 5 {
            return false;
        }
        let stored = rd_u32(a);
        let Some((hsize, hs_len)) = vint(&a[4..]) else {
            return false;
        };
        if hsize == 0 || hsize > V5_MAIN_HEADER_MAX {
            return false;
        }
        let hend = 4 + hs_len + hsize as usize;
        if a.len() < hend {
            return false;
        }
        if crc32fast::hash(&a[4..hend]) != stored {
            return false;
        }
        return matches!(vint(&a[4 + hs_len..hend]), Some((V5_TYPE_MAIN, _)));
    }
    if let Some(a) = bytes.strip_prefix(SIG4) {
        // Fixed intro: head_crc u16, head_type u8, flags u16, size u16.
        if a.len() < 7 || a[2] != V4_TYPE_MAIN {
            return false;
        }
        let hsize = rd_u16(&a[5..]) as usize;
        // 13 is the main header's own fixed length; `head_size` is a u16,
        // so it needs no upper cap.
        if hsize < 13 || a.len() < hsize {
            return false;
        }
        return matches!(v4_header_crc(a), V4HeaderCrc::Ok);
    }
    false
}

impl VolumeMapper {
    pub fn new(volume_size: u64) -> VolumeMapper {
        Self::with_password(volume_size, None)
    }

    /// A mapper that can parse RAR5 encrypted headers and accept
    /// encrypted store-mode entries (the password is check-verified
    /// against the archive before any entry is trusted).
    pub fn with_password(volume_size: u64, password: Option<std::sync::Arc<str>>) -> VolumeMapper {
        Self::with_password_at(volume_size, password, 0)
    }

    /// [`Self::with_password`] for an archive that starts `archive_base`
    /// bytes into the file - a self-extractor's payload behind its stub.
    /// The signature is expected AT that offset, not searched for: the
    /// caller has already located and confirmed it, and a mapper that
    /// scanned for itself would believe decoy constants inside the stub.
    pub fn with_password_at(
        volume_size: u64,
        password: Option<std::sync::Arc<str>>,
        archive_base: u64,
    ) -> VolumeMapper {
        VolumeMapper {
            version: None,
            entries: Vec::new(),
            blocker: None,
            volume_number: None,
            complete: false,
            volume_size,
            archive_base,
            state: ParseState::Signature,
            cursor: archive_base,
            win_base: archive_base,
            win: Vec::new(),
            win_off: 0,
            filled: Vec::new(),
            password,
            hdr_keys: None,
            v4_hdr_enc: false,
            crypt_seen: None,
        }
    }

    /// A mapper with NO parse of its own: the caller already knows every
    /// data area in this file and hands them over finished.
    ///
    /// It exists for the one-pass 7z direct map (TODO 37 step 4). A 7z
    /// container is not a RAR volume and has no incremental front-to-back
    /// header walk - its map is a single end header at the TAIL - but
    /// once that map is parsed, a Copy-coded member IS what a stored RAR
    /// member is: one contiguous range of the file whose bytes are the
    /// output's bytes. Everything the extractor does with a stored RAR
    /// volume from that point on (span routing, split bases, held-span
    /// re-feed, CRC composition, read-back reconstruction on a demote) is
    /// format-independent and reads only `entries` - so the 7z side
    /// builds those entries and borrows the machinery rather than growing
    /// a second copy of it.
    ///
    /// The mapper is born COMPLETE and `Done`: `feed` is a no-op that
    /// reports no progress (nothing can advance a parse that never ran),
    /// `mapped_through` is `u64::MAX`, so every byte outside a data area
    /// is header/meta and stashes for reconstruction. `version` stays
    /// `None` - this is not a RAR file and must not latch a RAR shape
    /// bit or take the RAR4 CRC arm in the settle gate.
    ///
    /// The caller owns two invariants `map_span_into` debug-asserts and
    /// the settle gate assumes: entries ORDERED by `data_off` and
    /// DISJOINT. Nothing here re-derives them, because nothing here can.
    pub fn synthetic(volume_size: u64, entries: Vec<FileEntry>) -> VolumeMapper {
        debug_assert!(
            entries
                .windows(2)
                .all(|w| w[0].data_off + w[0].data_len <= w[1].data_off),
            "synthetic mapper entries must be ordered and disjoint"
        );
        VolumeMapper {
            version: None,
            entries,
            blocker: None,
            volume_number: None,
            complete: true,
            volume_size,
            archive_base: 0,
            state: ParseState::Done,
            cursor: volume_size,
            win_base: volume_size,
            win: Vec::new(),
            win_off: 0,
            filled: Vec::new(),
            password: None,
            hdr_keys: None,
            v4_hdr_enc: false,
            crypt_seen: None,
        }
    }

    /// Where the archive begins inside the file (0 unless this mapper was
    /// built with [`Self::with_password_at`]). A re-keyed mapper must be
    /// rebuilt at the same base or it reads the stub as a signature.
    pub fn archive_base(&self) -> u64 {
        self.archive_base
    }

    /// Feed one decoded span. Returns true if the parse made progress -
    /// the cursor moved, or the volume finished - so the caller re-tries
    /// held spans and re-resolves bases.
    ///
    /// "Progress" is cursor movement, NOT "a new entry appeared". The
    /// window only keeps bytes near the cursor, so a span that lands
    /// past it is parked by the caller until the cursor catches up; a
    /// block that moves the cursor without adding an entry (a service
    /// block such as a multi-MB recovery record, skipped whole) still
    /// brings those parked bytes into reach. Measured 22 Aug 2026 on a
    /// `-rr10p` store set: the end block's article arrived before the
    /// record's header, the Skip advanced the cursor 10 MB with no
    /// entry, nothing re-fed the parked end block, and settle demoted
    /// the set as `incomplete mapping` on 2 of 13 runs.
    pub fn feed(&mut self, offset: u64, data: &[u8]) -> bool {
        if matches!(self.state, ParseState::Done) {
            return false;
        }
        self.stash(offset, data);
        let before = self.cursor;
        self.advance();
        self.cursor > before || matches!(self.state, ParseState::Done)
    }

    /// Copy the part of the span that overlaps the parse window.
    fn stash(&mut self, offset: u64, data: &[u8]) {
        // SATURATING, both of them. These are the first two operations
        // `feed` performs and both operands come straight off the wire:
        // a `.rar.NNN` split whose part 1 declares `=ybegin size=<u64
        // max>` gives `split_target` a logical offset of `u64::MAX`, and
        // a volume whose article carries no `size=` at all disarms
        // `advance_to`'s `volume_size > 0` guard so a RAR5 header can
        // walk `win_base` to just under `u64::MAX`. Honest yEnc reaches
        // neither - `check_part_geometry` pins `offset + len == end` -
        // so this is a hostile or badly corrupt post. Plain `+` panicked
        // in debug and wrapped in release (there is no `overflow-checks`
        // in the release profile, as `advance_to` records below); both
        // saturated forms fall through the `s >= e` guard immediately
        // below, which is the benign span-drop release already
        // performed, and nothing non-overflowing moves.
        let win_end = self.win_base.saturating_add(MAX_WIN as u64);
        let s = offset.max(self.win_base);
        let e = offset.saturating_add(data.len() as u64).min(win_end);
        if s >= e {
            return;
        }
        let need_len = (e - self.win_base) as usize;
        // The buffer stays bounded by MAX_WIN exactly as it was before
        // `win_off` existed: fold the dead prefix away rather than let
        // the live window sit above it. `need_len` is already clamped to
        // MAX_WIN by `win_end` above, so this is the only condition that
        // can ever be reached.
        if self.win_off > 0 && self.win_off + need_len > MAX_WIN {
            self.compact();
        }
        if self.win.len() < self.win_off + need_len {
            self.win.resize(self.win_off + need_len, 0);
        }
        let dst = (s - self.win_base) as usize;
        let src = (s - offset) as usize;
        let n = (e - s) as usize;
        self.win[self.win_off + dst..self.win_off + dst + n].copy_from_slice(&data[src..src + n]);
        merge_interval(&mut self.filled, dst, dst + n);
    }

    /// Contiguous bytes available at the cursor.
    fn avail(&self) -> &[u8] {
        debug_assert_eq!(self.win_base, self.cursor);
        match self.filled.first() {
            Some(&(0, e)) => {
                let live = self.win.len() - self.win_off;
                &self.win[self.win_off..self.win_off + e.min(live)]
            }
            _ => &[],
        }
    }

    /// Move the parse cursor to `next`, refusing a jump that does not advance.
    ///
    /// `next` is `base + header_size + data_len` over an attacker-declared
    /// 64-bit length, and release builds WRAP silently (no `overflow-checks`
    /// in the release profile). A RAR4 header declaring `data_len = 2^64 - 40`
    /// makes `next` land exactly back on the current block: `rebase` is then a
    /// no-op, the window is unchanged, and the Blocks loop re-parses the same
    /// bytes forever - pushing a fresh `FileEntry` (with a heap `String`) each
    /// pass, i.e. 100% CPU plus unbounded memory growth from any RAR volume in
    /// any downloaded NZB. A wrapped `next` BELOW `win_base` instead underflows
    /// `rebase`'s subtraction. Every block strictly advances, so require it.
    fn advance_to(&mut self, next: u64) -> bool {
        if next <= self.cursor {
            self.fail(MapBlocker::Corrupt("block length does not advance"));
            return false;
        }
        // A block whose data area RUNS OFF THE END of the volume. `next` is
        // header end + an attacker-declared `data_size`, and a merely-large
        // (non-wrapping) value passes the advance check above: the cursor
        // then lands past `volume_size`, the next parse finds an empty
        // window, and the EOF rule at the `NeedMore` arm below declares the
        // volume COMPLETE. The oversized entry stays in `entries` with a
        // data area nothing will ever fill, `mapped_through()` returns
        // u64::MAX so no tail-hold fires, and the extractor preallocates
        // the declared size and ships a mostly-sparse file as a successful
        // extraction. Refuse instead: `Corrupt` sets the blocker, the
        // extractor demotes to materialized volumes, and unrar fails the
        // job honestly.
        //
        // This never trips a real split set. `data_len` is the PER-VOLUME
        // packed portion, not the whole-file length - `ArchiveMap::resolve`
        // accumulates `data_len` ACROSS consecutive volumes to derive each
        // continuation's inner-file base - so every genuine block ends at or
        // before the volume end, which is the same invariant the EOF rule
        // already assumes (`cursor == volume_size` means complete). Guarded
        // on `volume_size > 0` because a yEnc span with no `size=` leaves it
        // unknown.
        if self.volume_size > 0 && next > self.volume_size {
            self.fail_volume_bound(next, self.volume_size);
            return false;
        }
        self.cursor = next;
        self.rebase(next);
        true
    }

    /// Refuse at the volume bound, naming BOTH terms on the way out.
    ///
    /// The blocker is a `&'static str`, so the reason a demoted set
    /// carries ("data area exceeds volume") says a bound was crossed and
    /// nothing whatever about WHICH side was wrong - which is exactly
    /// the question TODO 118 item 2 has been unable to answer since 5
    /// Aug 2026, when one reporter's post tripped this on 60 volume
    /// groups out of 60. The only evidence anyone will ever have of a
    /// field occurrence is that reporter's log, and until this line the
    /// log did not carry the arithmetic.
    ///
    /// `want` is where the header says the block ends; `have` is the
    /// volume length the POST declared, which is `=ybegin size=` (see
    /// `yenc::check_part_geometry`, whose note says in as many words
    /// that real posters get that field wrong on otherwise perfectly
    /// good articles, and that nothing here verifies it). The size of
    /// the overshoot is what separates the two explanations: measured 23
    /// Aug 2026 on RARLAB rar 7.23 store volumes, a healthy volume has
    /// only 8 bytes of tail slack (16 on a non-final volume), so an
    /// overshoot under a few hundred bytes means the DECLARATION is
    /// short by a trailing block or two, while an overshoot of megabytes
    /// means the header genuinely describes a data area this volume
    /// never held - a byte-split part 1 (TODO 211 b), or a packer
    /// writing the whole file's packed size into every volume.
    fn fail_volume_bound(&mut self, want: u64, have: u64) {
        tracing::warn!(
            target: "extract",
            "rar volume bound: block ends at {want}, post declares {have} bytes \
             (over by {}), volume={:?} archive_base={} - one-pass mapping refused",
            want.saturating_sub(have),
            self.volume_number,
            self.archive_base,
        );
        self.fail(MapBlocker::Corrupt("data area exceeds volume"));
    }

    /// Move the window base forward to `new_base` (>= win_base).
    ///
    /// THE DELTA IS COMPARED IN u64 AND NARROWED ONLY INSIDE THE DRAIN
    /// ARM. `(new_base - self.win_base) as usize` narrowed FIRST, and
    /// `usize` is 32 bits on the shipped armv7 target - so a rebase of
    /// exactly k*2^32 read as `skip == 0` and took the early `return`,
    /// which is the one exit that does NOT reach `self.win_base =
    /// new_base` at the foot. The cursor has already moved by then
    /// (`self.cursor = next; self.rebase(next);`), so the window would go
    /// on serving bytes from the OLD logical offset under the new
    /// cursor - `avail()` carries only a `debug_assert_eq!`, which the
    /// shipped artifact does not run. `k*2^32 + m` was the other half:
    /// it drained m bytes and then relabelled the survivors as living at
    /// `new_base`. This must NOT be written as a `chunk_len` clamp
    /// against `win.len()` - that answers 0 for an EMPTY window, which
    /// takes the same early return and reintroduces the desync from the
    /// other direction. See [`crate::disk::chunk_len`] for the class.
    fn rebase(&mut self, new_base: u64) {
        let delta = new_base - self.win_base;
        if delta == 0 {
            return;
        }
        if delta >= (self.win.len() - self.win_off) as u64 {
            self.win.clear();
            self.win_off = 0;
            self.filled.clear();
        } else {
            // Proven below the LIVE length, which is capped at MAX_WIN.
            let skip = delta as usize;
            // O(1) plus one in-place pass over `filled` (one interval in
            // the ordinary case): no memmove of the window and no fresh
            // Vec. The survivors stay sorted and disjoint - an interval
            // only survives when `e > skip`, and the list was already
            // ordered, so subtracting the same `skip` from every bound
            // preserves both properties.
            self.win_off += skip;
            self.filled.retain_mut(|(s, e)| {
                if *e > skip {
                    *s = s.saturating_sub(skip);
                    *e -= skip;
                    true
                } else {
                    false
                }
            });
        }
        self.win_base = new_base;
    }

    /// Fold the dead prefix `win[..win_off]` away, keeping the live
    /// window's bytes and their logical coordinates. Amortised: the only
    /// caller runs when a stash would otherwise grow the buffer past
    /// `MAX_WIN`, so a run of header advances pays ONE memmove instead
    /// of one per header.
    fn compact(&mut self) {
        if self.win_off == 0 {
            return;
        }
        let live = self.win.len() - self.win_off;
        self.win.copy_within(self.win_off.., 0);
        self.win.truncate(live);
        self.win_off = 0;
    }

    fn fail(&mut self, b: MapBlocker) {
        self.blocker = Some(b);
        self.state = ParseState::Done;
        self.win = Vec::new();
        self.win_off = 0;
        self.filled.clear();
    }

    pub(crate) fn advance(&mut self) {
        loop {
            match self.state {
                ParseState::Done => return,
                ParseState::Signature => {
                    let a = self.avail();
                    if a.len() < 8 {
                        if self.volume_size > 0
                            && self.volume_size < self.archive_base + 8
                            && self.archive_base + a.len() as u64 >= self.volume_size
                        {
                            self.fail(MapBlocker::NotRar);
                        }
                        return;
                    }
                    if &a[..8] == SIG5 {
                        self.version = Some(RarVersion::V5);
                        self.cursor = self.archive_base + 8;
                    } else if &a[..7] == SIG4 {
                        self.version = Some(RarVersion::V4);
                        self.cursor = self.archive_base + 7;
                    } else {
                        self.fail(MapBlocker::NotRar);
                        return;
                    }
                    self.rebase(self.cursor);
                    self.state = ParseState::Blocks;
                }
                ParseState::Blocks => {
                    let res = match self.version {
                        Some(RarVersion::V5) => match &self.hdr_keys {
                            Some(keys) => parse_block_v5_enc(self.avail(), self.cursor, keys),
                            None => parse_block_v5(self.avail(), self.cursor),
                        },
                        Some(RarVersion::V4) => match (self.v4_hdr_enc, &self.password) {
                            (true, Some(pw)) => {
                                parse_block_v4_enc(self.avail(), self.cursor, pw, self.volume_size)
                            }
                            // MHD_PASSWORD with no password: nothing past
                            // the main header can be read at all.
                            (true, None) => BlockResult::EncryptedHeaders,
                            (false, _) => parse_block_v4(self.avail(), self.cursor),
                        },
                        None => unreachable!(),
                    };
                    match res {
                        BlockResult::NeedMore => {
                            // EOF without an end block: v4 archives (and
                            // truncated v5) just stop.
                            if self.volume_size > 0 && self.cursor >= self.volume_size {
                                self.state = ParseState::Done;
                                self.complete = true;
                            }
                            return;
                        }
                        BlockResult::Corrupt(why) => {
                            self.fail(MapBlocker::Corrupt(why));
                            return;
                        }
                        BlockResult::EncryptedHeaders => {
                            self.fail(MapBlocker::EncryptedHeaders);
                            return;
                        }
                        BlockResult::BadPassword => {
                            self.fail(MapBlocker::BadPassword);
                            return;
                        }
                        BlockResult::V4EncryptedHeaders { next } => {
                            // With no password this volume is as opaque as
                            // it ever was; the decision is re-taken at the
                            // next block so the blocker still reads
                            // EncryptedHeaders rather than a parse error.
                            self.v4_hdr_enc = true;
                            if !self.advance_to(next) {
                                return;
                            }
                        }
                        BlockResult::Crypt {
                            next,
                            lg2_count,
                            salt,
                            check,
                        } => {
                            // RAR5 archive-encryption block: with a
                            // check-passing password, header parsing
                            // continues in decrypting mode; otherwise the
                            // volume is as opaque as it ever was. Stash the
                            // crypt params first (for the no-password probe)
                            // so a candidate can be tested even here.
                            if self.crypt_seen.is_none() {
                                self.crypt_seen = Some(CryptProbe {
                                    lg2_count,
                                    salt,
                                    check,
                                });
                            }
                            let Some(pw) = self.password.clone() else {
                                self.fail(MapBlocker::EncryptedHeaders);
                                return;
                            };
                            let Some(keys) = rarcrypt::derive_keys(&pw, &salt, lg2_count) else {
                                self.fail(MapBlocker::Corrupt("hostile KDF count"));
                                return;
                            };
                            if let Some(chk) = &check
                                && rarcrypt::check_rejects_password(&keys, chk)
                            {
                                self.fail(MapBlocker::BadPassword);
                                return;
                            }
                            self.hdr_keys = Some(keys);
                            if !self.advance_to(next) {
                                return;
                            }
                        }
                        BlockResult::End => {
                            self.state = ParseState::Done;
                            self.complete = true;
                            return;
                        }
                        BlockResult::Skip {
                            next,
                            volume_number,
                        } => {
                            if volume_number.is_some() {
                                self.volume_number = volume_number;
                            }
                            if !self.advance_to(next) {
                                return;
                            }
                        }
                        BlockResult::File { entry, next } => {
                            // Past the cap the volume stops being mapped.
                            // NotStore (not Corrupt) so it still routes
                            // through materialize + unrar, keeping the
                            // "never a hard job failure" property.
                            if self.entries.len() >= MAX_ENTRIES {
                                self.fail(MapBlocker::NotStore);
                                return;
                            }
                            if let Some(b) = self.entry_blocker(&entry) {
                                // Remember the entry (for diagnostics) but
                                // flag the volume unfit for direct extract.
                                self.entries.push(entry);
                                self.fail(b);
                                return;
                            }
                            self.entries.push(entry);
                            if !self.advance_to(next) {
                                return;
                            }
                        }
                    }
                }
            }
        }
    }

    /// Whether a parsed file entry blocks direct extraction. Encrypted
    /// STORE entries stay mappable when a password is in hand and nothing
    /// rejects it - the extractor then assembles the ciphertext stream at
    /// the usual store offsets and decrypts at finish.
    ///
    /// Only RAR5 can REJECT one here, via its stored check; that costs a
    /// KDF, cached per (password, salt, count), and a multi-volume set
    /// repeats one salt in every volume, so it is one derivation per
    /// archive rather than per volume. RAR4 has no check to test, so it
    /// derives nothing at all.
    fn entry_blocker(&self, e: &FileEntry) -> Option<MapBlocker> {
        if e.method == Method::Compressed {
            return Some(MapBlocker::NotStore);
        }
        if !e.encrypted {
            return None;
        }
        let Some(pw) = &self.password else {
            // No password anywhere: the verified volumes are the
            // deliverable until one arrives.
            return Some(MapBlocker::EncryptedNoPassword);
        };
        let Some(crypt) = &e.crypt else {
            // Encryption this parser has no key schedule for - a pre-3.0
            // RAR cipher (`unp_ver` < 29). Hand to unrar, which can use the
            // password we do have.
            return Some(MapBlocker::NotStore);
        };
        let Some(c) = crypt.rar5() else {
            // RAR4: the format stores nothing a password can be tested
            // against before decrypting, so this entry takes the same
            // unverified route a check-less RAR5 entry does - assemble the
            // posted CIPHERTEXT at store offsets (byte-identical to the
            // volumes, so a demote loses nothing) and let the finish pass
            // adjudicate against the header's whole-file CRC32, which for
            // RAR4 is a plain CRC of the PLAINTEXT.
            //
            // Answered BEFORE deriving anything, and not merely for speed:
            // a RAR4 salt is 8 attacker-chosen bytes in a plaintext file
            // header, and its schedule is 0x40000 SHA-1 rounds (~8x RAR5's
            // default). Deriving here would let a volume of back-to-back
            // distinct-salt file headers burn tens of CPU-minutes inside
            // the routing lock, bounded only by `MAX_ENTRIES`. Nothing here
            // needs the key, so nothing derives one; the finish pass
            // derives once per inner FILE, off the lock.
            return None;
        };
        let Some(keys) = crypt.derive(pw) else {
            return Some(MapBlocker::Corrupt("hostile KDF count"));
        };
        match &c.check {
            Some(chk)
                if keys
                    .psw_check
                    .is_some_and(|p| rarcrypt::check_rejects(&p, chk)) =>
            {
                Some(MapBlocker::BadPassword)
            }
            // Only a csum-VALID stored check actually verifies the password:
            // `check_rejects_password` deliberately refuses to veto on a
            // corrupt check (a damaged check must not condemn a correct
            // password). So "did not veto" is not the same as "verified" - a
            // check whose 4-byte SHA-256 tail is wrong vetoes NOTHING, for any
            // password, and it must never take the "verified" arm: an attacker
            // who also sets the tweaked-checksum flag would otherwise have a
            // wrong password native-decrypt garbage that ships as success.
            //
            // Such an entry (and a genuinely check-less one) is still
            // MAPPABLE, because the verdict has simply moved to finish.
            // It USED to assemble ciphertext for a decrypt pass to
            // adjudicate; since TODO 27 phase 3 it decrypts in-stream
            // like every other encrypted set - the re-encrypt shim
            // rebuilds byte-exact volumes even under a wrong key, so
            // nothing is lost by decrypting before the verdict - and
            // `verify_encrypted_outputs` requires the whole-file
            // checksum (the group's last piece carries it) to pass
            // before anything publishes. No checksum available there
            // means the group demotes and the volumes materialize,
            // which is exactly where this used to route immediately.
            Some(chk) if !rarcrypt::check_is_wellformed(chk) => None,
            Some(_) => None, // password verified - safe to native-decrypt
            // No stored check at all: same deal - unverifiable here,
            // adjudicated at finish against the whole-file checksum. Rare;
            // WinRAR writes a check by default.
            None => None,
        }
    }

    /// Map a decoded span (volume offset, len) onto parsed pieces.
    /// Returns (entry index, offset within the piece, offset within the
    /// span, len) for every intersection with a known data area. Parts of
    /// the span beyond the parsed region are NOT reported - the caller
    /// holds those bytes until more headers parse.
    pub fn map_span(&self, off: u64, len: u64) -> Vec<(usize, u64, u64, u64)> {
        let mut out = Vec::new();
        self.map_span_into(off, len, &mut out);
        out
    }

    /// [`Self::map_span`] into a caller-owned buffer - the article hot
    /// path reuses one scratch vector instead of allocating per article
    /// under the routing lock. Appends; the caller clears.
    pub fn map_span_into(&self, off: u64, len: u64, out: &mut Vec<(usize, u64, u64, u64)>) {
        let span_end = off + len;
        // Entries come off a forward-only parse cursor, so data areas are
        // ordered and disjoint; skip straight to the first one this span can
        // touch instead of scanning every parsed entry per article (this runs
        // under the routing lock for EVERY article of a many-member volume).
        debug_assert!(
            self.entries
                .windows(2)
                .all(|w| w[0].data_off + w[0].data_len <= w[1].data_off),
            "RAR entry data areas must be ordered and disjoint"
        );
        let start = self
            .entries
            .partition_point(|e| e.data_off + e.data_len <= off);
        for (i, e) in self.entries.iter().enumerate().skip(start) {
            if e.data_off >= span_end {
                break;
            }
            let ds = e.data_off;
            let de = e.data_off + e.data_len;
            let s = off.max(ds);
            let x = span_end.min(de);
            if s < x {
                out.push((i, s - ds, s - off, x - s));
            }
        }
    }

    /// Tell a mapper built with an UNKNOWN size (`0`) how long its volume
    /// really is, once the caller learns it. TODO 211 (b): a numbered
    /// byte split of one `.rar` (`x.rar.001`..) is a single volume whose
    /// extent is not in any header - part 1's header states its entry's
    /// data size and nothing about the container - so the extractor maps
    /// it open-ended and closes it here when the short last part reports.
    /// Re-runs the two `volume_size` rules the parse applied lazily: a
    /// cursor already past the new end is the same `data area exceeds
    /// volume` refusal `advance_to` makes (the declared data area cannot
    /// fit in the bytes that exist), and a parse parked at `NeedMore`
    /// exactly at the end completes by the EOF rule. A size of `0` is a
    /// no-op; so is a mapper that is already done.
    pub fn set_volume_size(&mut self, size: u64) {
        self.volume_size = size;
        if size == 0 || matches!(self.state, ParseState::Done) {
            return;
        }
        if self.cursor > size {
            self.fail_volume_bound(self.cursor, size);
            return;
        }
        self.advance();
    }

    /// The declared volume size this mapper was built with (`0` when the
    /// caller has not told it yet - see [`Self::set_volume_size`]).
    pub fn volume_size(&self) -> u64 {
        self.volume_size
    }

    /// The volume offset below which every byte is either header (parsed)
    /// or inside a known data area - i.e. mappable. Bytes at/after this
    /// need more header parsing.
    pub fn mapped_through(&self) -> u64 {
        if self.complete { u64::MAX } else { self.cursor }
    }
}

enum BlockResult {
    NeedMore,
    Corrupt(&'static str),
    EncryptedHeaders,
    /// A RAR4 header decrypted to something that is not a header, or whose
    /// CRC16 misses: with the right password neither can happen.
    BadPassword,
    /// RAR4 main header carrying MHD_PASSWORD: it and the marker are
    /// plaintext, every block from `next` onward is `salt + AES-128-CBC`.
    V4EncryptedHeaders {
        next: u64,
    },
    /// RAR5 archive-encryption block (type 4): all following headers are
    /// encrypted with keys derived from these parameters.
    Crypt {
        next: u64,
        lg2_count: u8,
        salt: [u8; 16],
        check: Option<[u8; 12]>,
    },
    End,
    /// Non-file block: next block starts at `next`. Main headers carry
    /// the RAR5 volume number when present.
    Skip {
        next: u64,
        volume_number: Option<u64>,
    },
    File {
        entry: FileEntry,
        next: u64,
    },
}

/// Read a RAR5 vint. Returns (value, bytes consumed) or None if truncated.
fn vint(b: &[u8]) -> Option<(u64, usize)> {
    let mut v: u64 = 0;
    for i in 0..10.min(b.len()) {
        v |= ((b[i] & 0x7f) as u64) << (7 * i);
        if b[i] & 0x80 == 0 {
            return Some((v, i + 1));
        }
    }
    None
}

fn rd_u32(b: &[u8]) -> u32 {
    u32::from_le_bytes(b[..4].try_into().unwrap())
}
fn rd_u16(b: &[u8]) -> u16 {
    u16::from_le_bytes(b[..2].try_into().unwrap())
}

/// Parse one RAR5 block whose header starts at `a[0]` (= volume offset
/// `base`).
fn parse_block_v5(a: &[u8], base: u64) -> BlockResult {
    // crc32(4) + header_size vint + header
    if a.len() < 5 {
        return BlockResult::NeedMore;
    }
    let stored_crc = rd_u32(a);
    let Some((hsize, hs_len)) = vint(&a[4..]) else {
        return if a.len() < 15 {
            BlockResult::NeedMore
        } else {
            BlockResult::Corrupt("bad header size vint")
        };
    };
    if hsize == 0 || hsize > (MAX_WIN as u64 - 16) {
        return BlockResult::Corrupt("implausible header size");
    }
    let hstart = 4 + hs_len;
    let hend = hstart + hsize as usize;
    if a.len() < hend {
        return BlockResult::NeedMore;
    }
    let hdr = &a[hstart..hend];
    // Per spec the CRC covers the header-size vint AND the header data.
    if crc32fast::hash(&a[4..hend]) != stored_crc {
        return BlockResult::Corrupt("header CRC mismatch");
    }
    parse_v5_body(hdr, base, hend as u64)
}

/// Parse one ENCRYPTED RAR5 block at `a[0]` (= volume offset `base`):
/// 16-byte IV, then AES-256-CBC ciphertext of the usual crc + size-vint +
/// header, padded to 16. The first cipher block is decrypted alone to
/// learn the header size, then the rest.
fn parse_block_v5_enc(a: &[u8], base: u64, keys: &rarcrypt::Rar5Keys) -> BlockResult {
    if a.len() < 32 {
        return BlockResult::NeedMore;
    }
    let iv: [u8; 16] = a[0..16].try_into().unwrap();
    let mut first = [0u8; 16];
    first.copy_from_slice(&a[16..32]);
    rarcrypt::cbc_decrypt(&keys.aes(), &iv, &mut first);
    let stored_crc = rd_u32(&first);
    let Some((hsize, hs_len)) = vint(&first[4..]) else {
        // 12 plaintext bytes hold any sane size vint.
        return BlockResult::Corrupt("bad encrypted header size vint");
    };
    if hsize == 0 || hsize > (MAX_WIN as u64 - 64) {
        return BlockResult::Corrupt("implausible header size");
    }
    let inner_len = 4 + hs_len + hsize as usize;
    let cipher_len = rarcrypt::align16(inner_len as u64) as usize;
    if a.len() < 16 + cipher_len {
        return BlockResult::NeedMore;
    }
    let mut plain = a[16..16 + cipher_len].to_vec();
    rarcrypt::cbc_decrypt(&keys.aes(), &iv, &mut plain);
    if crc32fast::hash(&plain[4..inner_len]) != stored_crc {
        // Wrong-password garbage is caught by the type-4 check value
        // before we ever get here - a CRC mismatch means damage.
        return BlockResult::Corrupt("encrypted header CRC mismatch");
    }
    let hdr = &plain[4 + hs_len..inner_len];
    parse_v5_body(hdr, base, (16 + cipher_len) as u64)
}

/// Parse a RAR5 header body (already decrypted if need be). `envelope` =
/// physical bytes the header occupies in the volume, so the block's data
/// area starts at `base + envelope`.
fn parse_v5_body(hdr: &[u8], base: u64, envelope: u64) -> BlockResult {
    let mut p = 0usize;
    let Some((btype, n)) = vint(&hdr[p..]) else {
        return BlockResult::Corrupt("type vint");
    };
    p += n;
    let Some((hflags, n)) = vint(&hdr[p..]) else {
        return BlockResult::Corrupt("flags vint");
    };
    p += n;
    let mut extra_size = 0u64;
    if hflags & 0x01 != 0 {
        let Some((v, n)) = vint(&hdr[p..]) else {
            return BlockResult::Corrupt("extra vint");
        };
        extra_size = v;
        p += n;
    }
    let mut data_size = 0u64;
    if hflags & 0x02 != 0 {
        let Some((v, n)) = vint(&hdr[p..]) else {
            return BlockResult::Corrupt("data vint");
        };
        data_size = v;
        p += n;
    }
    // CHECKED, exactly as the RAR4 twin below is and for the same
    // reason: `data_size` is an attacker-declared vint and `vint` will
    // return values within a few bytes of `u64::MAX`, so the plain sum
    // panics in debug and WRAPS in release. A wrapped `next` is small
    // but still greater than `cursor`, so it slips past both of
    // `advance_to`'s tests - defeating the very volume bound whose job
    // is to refuse a data area running off the end. The header CRC is
    // no defence: a poster stamps it over any fields at all.
    let Some(next) = base
        .checked_add(envelope)
        .and_then(|v| v.checked_add(data_size))
    else {
        return BlockResult::Corrupt("v5 block runs past the end of addressable space");
    };

    match btype {
        4 => {
            // Archive encryption block: version vint (0 = AES-256), flags
            // vint (0x01 = password check present), KDF count byte, salt.
            let Some((ver, n)) = vint(&hdr[p..]) else {
                return BlockResult::Corrupt("crypt version");
            };
            p += n;
            if ver != 0 {
                return BlockResult::EncryptedHeaders; // unknown scheme
            }
            let Some((cflags, n)) = vint(&hdr[p..]) else {
                return BlockResult::Corrupt("crypt flags");
            };
            p += n;
            if hdr.len() < p + 17 {
                return BlockResult::Corrupt("crypt salt");
            }
            let lg2_count = hdr[p];
            p += 1;
            let salt: [u8; 16] = hdr[p..p + 16].try_into().unwrap();
            p += 16;
            let mut check = None;
            if cflags & 0x01 != 0 && hdr.len() >= p + 12 {
                check = Some(<[u8; 12]>::try_from(&hdr[p..p + 12]).unwrap());
            }
            BlockResult::Crypt {
                next,
                lg2_count,
                salt,
                check,
            }
        }
        5 => BlockResult::End,
        1 => {
            // Main archive header: archive_flags vint, then volume number
            // (vint) when flag 0x02 is set. A volume archive (flag 0x01)
            // without an explicit number is the FIRST volume (0).
            let mut volume_number = None;
            if let Some((aflags, n)) = vint(&hdr[p..]) {
                if aflags & 0x02 != 0 {
                    if let Some((vn, _)) = vint(&hdr[p + n..]) {
                        volume_number = Some(vn);
                    }
                } else if aflags & 0x01 != 0 {
                    volume_number = Some(0);
                }
            }
            BlockResult::Skip {
                next,
                volume_number,
            }
        }
        2 | 3 => {
            // File (2) / service (3) header. Service blocks (CMT, QO, RR…)
            // carry data areas too and are skipped via `next`.
            if btype == 3 {
                return BlockResult::Skip {
                    next,
                    volume_number: None,
                };
            }
            let Some((file_flags, n)) = vint(&hdr[p..]) else {
                return BlockResult::Corrupt("file flags");
            };
            p += n;
            let Some((unp_size, n)) = vint(&hdr[p..]) else {
                return BlockResult::Corrupt("unpacked size");
            };
            p += n;
            let Some((_attr, n)) = vint(&hdr[p..]) else {
                return BlockResult::Corrupt("attributes");
            };
            p += n;
            if file_flags & 0x02 != 0 {
                if hdr.len() < p + 4 {
                    return BlockResult::Corrupt("mtime");
                }
                p += 4;
            }
            let mut file_crc = None;
            if file_flags & 0x04 != 0 {
                if hdr.len() < p + 4 {
                    return BlockResult::Corrupt("crc");
                }
                file_crc = Some(rd_u32(&hdr[p..]));
                p += 4;
            }
            let Some((comp_info, n)) = vint(&hdr[p..]) else {
                return BlockResult::Corrupt("compression info");
            };
            p += n;
            let Some((_host, n)) = vint(&hdr[p..]) else {
                return BlockResult::Corrupt("host os");
            };
            p += n;
            let Some((name_len, n)) = vint(&hdr[p..]) else {
                return BlockResult::Corrupt("name len");
            };
            p += n;
            if name_len > 0xFFFF || hdr.len() < p + name_len as usize {
                return BlockResult::Corrupt("name");
            }
            let name = String::from_utf8_lossy(&hdr[p..p + name_len as usize]).into_owned();

            // Extra area: scan records for file-encryption (type 0x01)
            // and the file-hash record (type 0x02), lifting decryption
            // parameters and any stored integrity digest.
            let mut encrypted = false;
            let mut crypt = None;
            let mut hash = None;
            if extra_size > 0 {
                let ex_start = hdr.len().saturating_sub(extra_size as usize);
                let mut q = ex_start;
                while q < hdr.len() {
                    let Some((rec_size, n)) = vint(&hdr[q..]) else {
                        break;
                    };
                    let rec_start = q + n;
                    if rec_start >= hdr.len() {
                        break;
                    }
                    let Some((rec_type, tn)) = vint(&hdr[rec_start..]) else {
                        break;
                    };
                    // rec_size spans the type vint PLUS the record body, so it
                    // must be >= tn AND fit within the header; without the lower
                    // bound a crafted rec_size < tn makes the slice start exceed
                    // its end and panics.
                    let body_ok =
                        rec_size as usize >= tn && rec_size as usize <= hdr.len() - rec_start;
                    if rec_type == 0x01 {
                        encrypted = true;
                        if body_ok {
                            crypt = parse_crypt_record(
                                &hdr[rec_start + tn..rec_start + rec_size as usize],
                            );
                        }
                    } else if rec_type == 0x02 && body_ok {
                        // FHEXTRA_HASH: hash_type vint then the raw digest.
                        let body = &hdr[rec_start + tn..rec_start + rec_size as usize];
                        if let Some((htype, hn)) = vint(body) {
                            hash = Some((htype, body[hn..].to_vec()));
                        }
                    }
                    // A hostile rec_size near 2^64 wrapped this addition
                    // (release profile: no overflow checks) and mapped q
                    // onto itself - an infinite loop holding the
                    // extractor's global lock. Bound it instead.
                    if rec_size as usize > hdr.len() - rec_start {
                        break;
                    }
                    q = rec_start + rec_size as usize;
                }
            }

            let method_bits = (comp_info >> 7) & 0x7;
            let is_dir = file_flags & 0x01 != 0;
            BlockResult::File {
                entry: FileEntry {
                    name,
                    unpacked_size: unp_size,
                    method: if method_bits == 0 {
                        Method::Store
                    } else {
                        Method::Compressed
                    },
                    encrypted,
                    crypt,
                    file_crc,
                    hash,
                    is_dir,
                    size_unknown: file_flags & 0x08 != 0,
                    split_before: hflags & 0x08 != 0,
                    split_after: hflags & 0x10 != 0,
                    data_off: base + envelope,
                    data_len: data_size,
                },
                next,
            }
        }
        _ => BlockResult::Skip {
            next,
            volume_number: None,
        }, // main header (1), unknown types
    }
}

/// File-encryption extra record body (after the record-type vint):
/// version vint (0), flags vint (0x01 check present, 0x02 tweaked
/// checksums), KDF count byte, 16-byte salt, 16-byte IV, optional
/// 12-byte check.
fn parse_crypt_record(rec: &[u8]) -> Option<EntryCrypt> {
    let (ver, mut p) = vint(rec)?;
    if ver != 0 {
        return None;
    }
    let (cflags, n) = vint(&rec[p..])?;
    p += n;
    if rec.len() < p + 33 {
        return None;
    }
    let lg2_count = rec[p];
    p += 1;
    let salt: [u8; 16] = rec[p..p + 16].try_into().unwrap();
    p += 16;
    let iv: [u8; 16] = rec[p..p + 16].try_into().unwrap();
    p += 16;
    let check = (cflags & 0x01 != 0 && rec.len() >= p + 12)
        .then(|| <[u8; 12]>::try_from(&rec[p..p + 12]).unwrap());
    Some(EntryCrypt::Rar5(Rar5Crypt {
        lg2_count,
        salt,
        iv,
        check,
        tweaked_checksum: cflags & 0x02 != 0,
    }))
}

/// RAR4 `FHD_UNICODE` flag: the file-name field is `asciiFallback` + `\0` +
/// `highByte` + a 2-bit-mode packed UTF-16 stream (WinRAR's custom encoding).
const FHD_UNICODE: u16 = 0x0200;

/// Decode a RAR4 file-name field into UTF-8 bytes. Without the unicode flag
/// (or when the field lacks the `\0` separator) the raw bytes pass through.
/// The 2-bit-mode decoder mirrors the vendored codec's `decode_file_name`.
fn decode_rar4_name(raw: &[u8], flags: u16) -> Vec<u8> {
    if flags & FHD_UNICODE == 0 {
        return raw.to_vec();
    }
    let Some(zero_pos) = raw.iter().position(|&b| b == 0) else {
        return raw.to_vec();
    };
    if zero_pos + 1 >= raw.len() {
        return raw[..zero_pos].to_vec();
    }
    let fallback = &raw[..zero_pos];
    let high_byte = raw[zero_pos + 1];
    let encoded = &raw[zero_pos + 2..];
    let mut pos = 0usize;
    let mut flag_byte = 0u8;
    let mut flag_bits = 0u8;
    let mut dst_pos = 0usize;
    let mut units: Vec<u16> = Vec::new();
    // WinRAR's decoder stops at `MaxDecSize` (NM); without a ceiling the
    // mode-3 run expands up to 129 output units per encoded byte, and each
    // unit costs up to 3 UTF-8 bytes. A ceiling counted per HEADER does not
    // bound the volume: a 70-byte file header whose 38-byte name field is an
    // all-0xFF run decodes to 6 KB of String, RETAINED in the mapper's entry
    // list, so back-to-back headers amplify ~88x and turn a ~100 MB volume
    // into ~9 GB resident from any NZB. Bound the output by the ENCODED field
    // instead. Real names are unaffected: modes 0/1 emit at most one unit per
    // byte, mode 2 one per two, and a legitimate mode-3 run copies from the
    // ASCII fallback, whose length is below `raw.len()`. Amplification is then
    // capped at 3x, matching RAR5.
    const MAX_NAME_UNITS: usize = 2048;
    let cap = MAX_NAME_UNITS.min(raw.len());
    while pos < encoded.len() && units.len() < cap {
        if flag_bits == 0 {
            flag_byte = encoded[pos];
            pos += 1;
            flag_bits = 8;
        }
        let mode = flag_byte >> 6;
        flag_byte <<= 2;
        flag_bits -= 2;
        match mode {
            0 => {
                let Some(&low) = encoded.get(pos) else {
                    return raw.to_vec();
                };
                pos += 1;
                units.push(u16::from(low));
                dst_pos += 1;
            }
            1 => {
                let Some(&low) = encoded.get(pos) else {
                    return raw.to_vec();
                };
                pos += 1;
                units.push((u16::from(high_byte) << 8) | u16::from(low));
                dst_pos += 1;
            }
            2 => {
                let Some((&low, &high)) = encoded.get(pos).zip(encoded.get(pos + 1)) else {
                    return raw.to_vec();
                };
                pos += 2;
                units.push((u16::from(high) << 8) | u16::from(low));
                dst_pos += 1;
            }
            _ => {
                let Some(&length_byte) = encoded.get(pos) else {
                    return raw.to_vec();
                };
                pos += 1;
                let (count, correction, high) = if length_byte & 0x80 != 0 {
                    let Some(&correction) = encoded.get(pos) else {
                        return raw.to_vec();
                    };
                    pos += 1;
                    ((length_byte & 0x7f) as usize + 2, correction, high_byte)
                } else {
                    (length_byte as usize + 2, 0, 0)
                };
                // Clamp the run to the same ceiling - the loop guard above
                // only sees whole iterations, and one run can emit 129 units.
                let count = count.min(cap - units.len());
                for _ in 0..count {
                    let low = fallback
                        .get(dst_pos)
                        .copied()
                        .unwrap_or(b'?')
                        .wrapping_add(correction);
                    units.push((u16::from(high) << 8) | u16::from(low));
                    dst_pos += 1;
                }
            }
        }
    }
    char::decode_utf16(units)
        .map(|u| u.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect::<String>()
        .into_bytes()
}

/// RAR4 file flag `FHD_SALT`: an 8-byte encryption salt follows the name.
const FHD_SALT: u16 = 0x0400;

/// RAR4 file flag `FHD_ENCRYPTED`.
const FHD_ENCRYPTED: u16 = 0x0004;

/// Lowest `unp_ver` whose encryption is the AES-128 + SHA-1 schedule this
/// crate implements (unrar's `CRYPT_RAR30`; the vendored rars fork draws
/// the same line in `SplitCipher::new`). Below it lie the pre-3.0 ciphers
/// (RAR 1.3/1.5/2.0), which stay on the unrar fallback: they predate the
/// obfuscated-release era by two decades and share no primitives.
const RAR4_AES_MIN_UNP_VER: u8 = 29;

/// Parse one RAR4 block at `a[0]` (= volume offset `base`).
fn parse_block_v4(a: &[u8], base: u64) -> BlockResult {
    parse_block_v4_at(a, base, None)
}

/// Parse one RAR4 block whose (already decrypted, for `-hp`) header bytes
/// start at `h[0]`.
///
/// `hdr_span` is how many bytes the header occupies IN THE VOLUME, which
/// is `hsize` for a plaintext block but `8 + align16(hsize)` for an
/// encrypted one (salt + AES padding) - so it decides where the data area
/// starts and where the next block begins. `None` means "plaintext, use
/// `hsize`", which also tells the parser it may still need more bytes.
fn parse_block_v4_at(h: &[u8], base: u64, hdr_span: Option<u64>) -> BlockResult {
    let a = h;
    if a.len() < 7 {
        return BlockResult::NeedMore;
    }
    let btype = a[2];
    let flags = rd_u16(&a[3..]);
    let hsize = rd_u16(&a[5..]) as usize;
    if hsize < 7 {
        return BlockResult::Corrupt("v4 header size < 7");
    }
    let mut add_size = 0u64;
    if flags & 0x8000 != 0 {
        if a.len() < 11 {
            return BlockResult::NeedMore;
        }
        add_size = rd_u32(&a[7..]) as u64;
    }
    if a.len() < hsize {
        return BlockResult::NeedMore;
    }
    // Every field below - the name, the flags, the geometry the
    // extractor turns into pwrite destinations - is authoritative only
    // if the header that carries them is intact, and RAR4 ships a CRC16
    // saying so. The `-hp` path has always checked it (there it also
    // adjudicates the password); RAR5 checks its own at both entry
    // points. The plaintext RAR4 path did not, so damaged or crafted
    // header bytes were trusted (Codex sweep 10 Aug, M5).
    //
    // Only on the plaintext entry: an encrypted block arrives here with
    // `hdr_span` set, and `parse_block_v4_enc_with` has already checked
    // the same CRC over the same bytes.
    if hdr_span.is_none() {
        match v4_header_crc(a) {
            V4HeaderCrc::Ok => {}
            V4HeaderCrc::Mismatch => return BlockResult::Corrupt("v4 header CRC mismatch"),
            // A unix-owner sub-block is checksummed over the names in its
            // data area, so the check waits for them like any other header
            // field that has not arrived yet.
            V4HeaderCrc::NeedMore => return BlockResult::NeedMore,
        }
    }
    let span = hdr_span.unwrap_or(hsize as u64);
    // Every `next` below is arithmetic over attacker-declared fields, so
    // it is CHECKED: `high_pack = 0xFFFF_FFFF` puts `data_len` within a
    // few bytes of `u64::MAX` and the plain sum then panics in debug and
    // wraps in release - a wrapped cursor being exactly the shape the
    // mapper's strict-advance rule exists to catch. Found by the RAR4
    // plaintext fuzz half added with the M5 CRC gate; the gate makes it
    // unreachable by ACCIDENT, never by a poster, who can stamp a
    // correct CRC over any fields at all.
    let end_of = |data: u64| -> Option<u64> { base.checked_add(span)?.checked_add(data) };
    // NOTE: for file headers with the 0x100 flag, `add_size` here is only
    // the LOW 32 bits - the file branch recomputes `next` with the high
    // half once parsed (a >4 GiB RAR4 store piece would otherwise walk
    // the cursor into the data area and end in a Corrupt fallback).
    let Some(next) = end_of(add_size) else {
        return BlockResult::Corrupt("v4 block runs past the end of addressable space");
    };

    match btype {
        0x73 => {
            // Main header: MHD_PASSWORD (0x0080) = every block AFTER this
            // one is encrypted. The marker and the main header itself stay
            // plaintext (unrar's `ReadHeader15` only decrypts past
            // `SIZEOF_MARKHEAD3`), which is what makes the flag readable at
            // all.
            if flags & 0x0080 != 0 {
                BlockResult::V4EncryptedHeaders { next }
            } else {
                BlockResult::Skip {
                    next,
                    volume_number: None,
                }
            }
        }
        0x74 => {
            // File header. Layout after the 7+4 byte block intro:
            // unp_size u32, host u8, crc u32, time u32, unp_ver u8,
            // method u8, name_size u16, attr u32,
            // [high_pack u32, high_unp u32 if flags & 0x100], name.
            if a.len() < 32 {
                return BlockResult::NeedMore;
            }
            let mut p = 11;
            let mut unp_size = rd_u32(&a[p..]) as u64;
            p += 4; // unp
            p += 1; // host
            // RAR4 stores a plain CRC32 of the unpacked data here - of the
            // PLAINTEXT even on an encrypted entry (unrar checks it after
            // decrypting, and the vendored rars writer stamps
            // `crc32(unpacked)` on the final fragment). Capturing it feeds
            // the final-output verifier so a tampered STORE member (damaged
            // before posting, so outer yEnc/PAR2 verify the archive
            // as-posted) is caught instead of written out as success; for an
            // encrypted entry it is also the ONLY thing that can adjudicate
            // the password, since RAR4 stores no check value.
            let v4_crc = rd_u32(&a[p..]);
            p += 4; // crc
            p += 4; // time
            let unp_ver = a[p];
            p += 1; // unp_ver
            let method = a[p];
            p += 1;
            let name_size = rd_u16(&a[p..]) as usize;
            p += 2;
            p += 4; // attr
            let mut data_len = add_size;
            if flags & 0x0100 != 0 {
                if a.len() < p + 8 {
                    return BlockResult::NeedMore;
                }
                data_len |= (rd_u32(&a[p..]) as u64) << 32;
                unp_size |= (rd_u32(&a[p + 4..]) as u64) << 32;
                p += 8;
            }
            if a.len() < p + name_size || p + name_size > hsize {
                if p + name_size > hsize {
                    return BlockResult::Corrupt("v4 name exceeds header");
                }
                return BlockResult::NeedMore;
            }
            // RAR4 encodes non-ASCII names with the FHD_UNICODE flag (0x0200)
            // as `asciiFallback\0<highByte><2-bit-packed UTF-16>`; a plain
            // UTF-8-lossy decode of the whole field mangles them (and two
            // distinct encoded names could collapse to one). Decode the
            // structure first.
            let name = String::from_utf8_lossy(&decode_rar4_name(&a[p..p + name_size], flags))
                .into_owned();
            p += name_size;
            let encrypted = flags & FHD_ENCRYPTED != 0;
            // The 8-byte encryption salt sits immediately after the name.
            // Absent it, the key schedule runs over the password alone -
            // a legacy shape, but a legal one, so parse the flag rather
            // than requiring a salt.
            let salt: Option<[u8; 8]> = if flags & FHD_SALT != 0 {
                if p + 8 > hsize {
                    return BlockResult::Corrupt("v4 salt exceeds header");
                }
                if a.len() < p + 8 {
                    return BlockResult::NeedMore;
                }
                Some(a[p..p + 8].try_into().unwrap())
            } else {
                None
            };
            // Only RAR 3.0+ encryption has a key schedule here. Older
            // ciphers leave `crypt` empty, which `entry_blocker` reads as
            // "hand to unrar".
            let crypt = (encrypted && unp_ver >= RAR4_AES_MIN_UNP_VER)
                .then_some(EntryCrypt::Rar4(Rar4Crypt { salt }));
            let decryptable = crypt.is_some();
            let is_dir = flags & 0x00E0 == 0x00E0;
            // The full 64-bit length, so this is the sum that can leave
            // the address space - `next` above only carried the low 32.
            let Some(data_end) = end_of(data_len) else {
                return BlockResult::Corrupt("v4 data area runs past the end of addressable space");
            };
            BlockResult::File {
                entry: FileEntry {
                    name,
                    unpacked_size: unp_size,
                    method: if method == 0x30 {
                        Method::Store
                    } else {
                        Method::Compressed
                    },
                    encrypted,
                    crypt,
                    // A zero field reads as "not computed", not as a real
                    // CRC32 of 0: writers leave it zero on pieces they can't
                    // compute a whole-file digest for, and the output gate
                    // treats a present CRC as authoritative - so trusting a 0
                    // would false-demote (deleting the extracted output and
                    // forcing a materialize+unrar) on a perfectly good set.
                    // The only real data hashing to 0 is an empty file, which
                    // has nothing to verify anyway.
                    //
                    // An encrypted entry carries it only when we can actually
                    // decrypt: with no key schedule the set materializes and
                    // unrar owns the verdict, and the value would just be a
                    // plaintext CRC nothing in this process ever computes.
                    // Note this is the WHOLE-FILE plaintext CRC only on the
                    // last fragment (`!split_after`); earlier fragments of a
                    // split encrypted file describe their own volume's packed
                    // bytes, which is why the finish pass reads the tail's.
                    file_crc: (!encrypted || decryptable)
                        .then_some(v4_crc)
                        .filter(|&c| c != 0),
                    hash: None,
                    is_dir,
                    // RAR4 has no unknown-size flag this parser honors.
                    size_unknown: false,
                    split_before: flags & 0x0001 != 0,
                    split_after: flags & 0x0002 != 0,
                    data_off: base + span,
                    data_len,
                },
                // Full 64-bit data length, not the low-32 `add_size`.
                next: data_end,
            }
        }
        0x7b => BlockResult::End,
        _ => BlockResult::Skip {
            next,
            volume_number: None,
        },
    }
}

/// A RAR4 header is CRC16-checked (`crc32(header[2..end]) & 0xffff`),
/// which is what lets the `-hp` path tell a wrong password from a real
/// header: garbage decrypts to a CRC that misses with probability
/// 1 - 2^-16 per block.
///
/// The covered range stops short of the full header for the two legacy
/// comment shapes, where WinRAR CRCs only the fixed part, and runs PAST it
/// for a RAR 2.x unix-owner sub-block - mirrored from the vendored rars
/// fork's `header_crc_end`, which is what real archives are known to match.
enum V4HeaderCrc {
    /// The covered range checksums to the value the header stores.
    Ok,
    /// It does not, so nothing the header declares is authoritative.
    Mismatch,
    /// The covered range runs past the bytes buffered so far. Only a
    /// unix-owner sub-block can do this: its range extends into the data
    /// area, which the caller has not been asked to buffer.
    NeedMore,
}

fn v4_header_crc(h: &[u8]) -> V4HeaderCrc {
    let hsize = rd_u16(&h[5..]) as usize;
    if h.len() < hsize {
        return V4HeaderCrc::Mismatch;
    }
    let btype = h[2];
    let flags = rd_u16(&h[3..]);
    const MHD_COMMENT: u16 = 0x0002;
    const FHD_COMMENT: u16 = 0x0008;
    const FHD_LARGE: u16 = 0x0100;
    let end = match btype {
        // Main header with an old-style archive comment, and the standalone
        // comment block: fixed 13-byte coverage.
        //
        // 13 is also these blocks' own fixed length, so a `head_size`
        // under it declares a block too small to hold the range its CRC
        // covers. Taking the range anyway read PAST the header: off the
        // end of the buffer when only a short read had arrived (a panic,
        // found 13 Aug by `rar_name_probe` fuzzing on a 10-byte 0x73
        // header declaring `head_size` 8), or silently into the NEXT
        // block's bytes when more had. Neither is a real archive - WinRAR
        // never writes one, and `archive_starts_here` has always refused
        // `hsize < 13` outright - so a header claiming this is not
        // authoritative about anything.
        0x73 if flags & MHD_COMMENT != 0 => {
            if hsize < 13 {
                return V4HeaderCrc::Mismatch;
            }
            13
        }
        0x75 => {
            if hsize < 13 {
                return V4HeaderCrc::Mismatch;
            }
            13
        }
        // File header with an old-style comment: coverage stops after the
        // salt, before the comment area. `name_size` sits at +26 (+28 is the
        // attribute word) - reading the wrong field here made every
        // commented file header miss its CRC.
        0x74 | 0x7a if flags & FHD_COMMENT != 0 => {
            if h.len() < 32 {
                return V4HeaderCrc::Mismatch;
            }
            let name_size = rd_u16(&h[26..]) as usize;
            let mut e = 32;
            if flags & FHD_LARGE != 0 {
                e += 8;
            }
            e += name_size;
            if flags & FHD_SALT != 0 {
                e += 8;
            }
            e.min(hsize)
        }
        // Unix-owner sub-block: the owner and group names live past
        // `head_size`, and the CRC covers them. See `v4_uo_crc_extra`.
        _ => match v4_uo_crc_extra(h, btype, flags, hsize) {
            Some(extra) => {
                let end = hsize + extra;
                if end > h.len() {
                    return V4HeaderCrc::NeedMore;
                }
                end
            }
            None => hsize,
        },
    };
    // The fixed-coverage arms (13 for the comment shapes) trust nothing
    // about the buffer: a crafted block declaring `hsize` under its own
    // coverage passes the caller's `len >= hsize` guard and would slice
    // past the end here (fuzz find, 13 Aug 2026 - rar_name_probe). A
    // real comment block is never shorter than its covered range, so a
    // range the buffer cannot contain is a header lying about its own
    // size: Mismatch, not NeedMore (the unix-owner arm, the one shape
    // whose coverage legitimately outruns the buffer, returned NeedMore
    // above before this point).
    if end < 2 || end > h.len() {
        return V4HeaderCrc::Mismatch;
    }
    if (crc32fast::hash(&h[2..end]) & 0xffff) as u16 == rd_u16(h) {
        V4HeaderCrc::Ok
    } else {
        V4HeaderCrc::Mismatch
    }
}

/// How many bytes PAST `head_size` the CRC of a RAR 2.x unix-owner
/// sub-block (`0x77`, sub type `UO_HEAD` = `0x0101`) covers, or `None` when
/// the block is not one.
///
/// The block declares an owner and a group name size but stores the names
/// themselves in its data area. unrar reads both into the same raw header
/// buffer before checksumming it, so the CRC WinRAR stamped covers them -
/// checksumming only `head_size` rejects archives `rar` and `unrar` read.
/// Keyed on the sub type, not on the data size: other sub-block flavours
/// carry a payload their CRC does not cover. Same rule, same reasoning as
/// the vendored fork's `unix_owner_crc_extra`.
fn v4_uo_crc_extra(h: &[u8], btype: u8, flags: u16, hsize: usize) -> Option<usize> {
    /// The fixed part: short header, data size (`0x77` always carries
    /// `LONG_BLOCK`), sub type, level, and the two name sizes.
    const SIZEOF_UOWNERHEAD: usize = 18;
    if btype != 0x77
        || flags & 0x8000 == 0
        || hsize < SIZEOF_UOWNERHEAD
        || h.len() < SIZEOF_UOWNERHEAD
    {
        return None;
    }
    if rd_u16(&h[11..]) != 0x0101 {
        return None;
    }
    Some(rd_u16(&h[14..]) as usize + rd_u16(&h[16..]) as usize)
}

/// Parse one AES-128-CBC encrypted RAR4 block (`-hp`) at volume offset
/// `base`.
///
/// On-disk shape, per unrar's `Archive::ReadHeader15` and the vendored
/// rars fork's `decrypt_encrypted_header_at`: an 8-byte plaintext salt,
/// then `align16(head_size)` bytes of ciphertext. Each block is its OWN
/// CBC stream restarting from the schedule's IV, so `head_size` has to be
/// read out of the first decrypted block before the rest can be sized.
/// Real archives repeat one salt for every header, which the KDF cache
/// turns into a single key derivation per volume.
fn parse_block_v4_enc(a: &[u8], base: u64, password: &str, volume_size: u64) -> BlockResult {
    if a.len() < 24 {
        return BlockResult::NeedMore;
    }
    let salt: [u8; 8] = a[..8].try_into().unwrap();
    let keys = rarcrypt::derive_keys_v4(password, Some(salt));
    parse_block_v4_enc_with(a, base, &keys, volume_size)
}

/// [`parse_block_v4_enc`] with the key schedule already run.
///
/// Split out because every length and offset below comes from decrypted
/// attacker bytes while the schedule above is fixed-size arithmetic over a
/// password: the fuzz target drives THIS with one throwaway key, so the
/// framing gets millions of executions instead of the ~20/s that 0x40000
/// SHA-1 rounds per input would allow.
fn parse_block_v4_enc_with(
    a: &[u8],
    base: u64,
    keys: &rarcrypt::Rar4Keys,
    volume_size: u64,
) -> BlockResult {
    if a.len() < 24 {
        return BlockResult::NeedMore;
    }
    let aes = rarcrypt::AesKey::Aes128(keys.key);
    let mut first = [0u8; 16];
    first.copy_from_slice(&a[8..24]);
    rarcrypt::cbc_decrypt(&aes, &keys.iv, &mut first);
    let hsize = rd_u16(&first[5..]) as usize;
    let enc_len = (hsize + 15) & !15;
    // Three cheap sanity checks on the decrypted first block BEFORE the
    // header CRC, because the CRC needs `hsize` bytes and a wrong password
    // yields a random `hsize` of up to 64 KB: without them the parser would
    // sit in NeedMore for bytes the volume does not contain, never reaching
    // a verdict, and the extractor would hold spans until the budget blew.
    // With the right password all three hold by construction.
    let plausible = hsize >= 7
        && (0x72..=0x7b).contains(&first[2])
        && (volume_size == 0 || base + 8 + enc_len as u64 <= volume_size);
    if !plausible {
        // Not a header shape at all - so the password is the suspect. Same
        // verdict RAR5's stored check gives, and the finish ladder prompts
        // for a new one instead of shipping anything.
        return BlockResult::BadPassword;
    }
    if a.len() < 8 + enc_len {
        return BlockResult::NeedMore;
    }
    let mut hdr = Vec::with_capacity(enc_len);
    hdr.extend_from_slice(&first);
    hdr.extend_from_slice(&a[24..8 + enc_len]);
    // One stream: the first block is already decrypted, so continue the
    // chain from its ciphertext rather than restarting at the IV.
    let chain: [u8; 16] = a[8..24].try_into().unwrap();
    rarcrypt::cbc_decrypt(&aes, &chain, &mut hdr[16..]);
    hdr.truncate(hsize);
    // `NeedMore` here means a unix-owner sub-block whose trailing names were
    // cut off by the truncate above: they are ciphertext in the data area,
    // outside this decrypt window. It is not a password verdict, so the
    // oracle stands down for that one block rather than calling a correct
    // password wrong. RAR 2.x sub-blocks predate this AES schedule by two
    // major versions, so a real archive cannot reach it.
    if matches!(v4_header_crc(&hdr), V4HeaderCrc::Mismatch) {
        return BlockResult::BadPassword;
    }
    match parse_block_v4_at(&hdr, base, Some(8 + enc_len as u64)) {
        // Every byte the header declares is already here, so "feed me
        // more" can only mean the header's own fields overrun its
        // `head_size` - malformed, not incomplete. Left as NeedMore the
        // parser would ask for bytes that will never come and the volume
        // would never reach a verdict at all.
        BlockResult::NeedMore => BlockResult::Corrupt("v4 encrypted header overruns its size"),
        other => other,
    }
}

/// Insert `[s, e]` into a sorted, disjoint, non-adjacent interval list,
/// absorbing everything it touches.
///
/// IN PLACE, and that is the point: this runs once per stashed span -
/// i.e. once per article on the one-pass path, under the extractor's
/// routing lock - and the fresh `Vec` plus sort it used to build was
/// per-article allocator traffic in exactly that critical section. The
/// list is kept sorted and disjoint by this function alone (and shifted
/// wholesale by `VolumeMapper::rebase`), so the two binary searches are
/// over a monotone predicate.
///
/// The merge condition is TOUCHING, not overlapping - `fe < s` and
/// `fs > e` are the two "keep it separate" cases the old fold used, so
/// an interval that merely abuts is absorbed, exactly as before.
fn merge_interval(list: &mut Vec<(usize, usize)>, mut s: usize, mut e: usize) {
    debug_assert!(list.windows(2).all(|w| w[0].1 < w[1].0));
    let lo = list.partition_point(|&(_, fe)| fe < s);
    let hi = list.partition_point(|&(fs, _)| fs <= e);
    if lo < hi {
        s = s.min(list[lo].0);
        e = e.max(list[hi - 1].1);
        list[lo] = (s, e);
        list.drain(lo + 1..hi);
    } else {
        list.insert(lo, (s, e));
    }
}

/// Does this on-disk volume need a password? Feeds the file's head
/// through the header parser: encrypted headers (RAR4 MHD_PASSWORD /
/// RAR5 encryption block) or any password-protected file entry (headers
/// readable, data encrypted). Merely-compressed archives return false -
/// those unrar can unpack without a password.
pub fn needs_password(path: &std::path::Path) -> bool {
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let size = f.metadata().map(|m| m.len()).unwrap_or(0);
    let mut m = VolumeMapper::new(size);
    // Seek-driven so an encrypted entry BEHIND a large plaintext member is
    // still detected (finding 17), not just one in the first 512 KiB.
    feed_headers_incrementally(&mut f, size, &mut m);
    matches!(m.blocker, Some(MapBlocker::EncryptedHeaders)) || m.entries.iter().any(|e| e.encrypted)
}

/// Are this volume's headers opaque to the streaming mapper even WITH
/// `password` in hand? True says the in-stream path cannot map the set at
/// all, so extracting it means reading the volumes off disk through the
/// rars fork or unrar.
///
/// The shape it exists for is `-hp` (encrypted headers). Both formats now
/// parse on with the right password - RAR5 through its type-4 encryption
/// block, RAR4 through the per-block salt + AES-128 headers - so both
/// answer false and keep their in-stream route. RAR4 `-hp` used to answer
/// TRUE whatever it was handed, because header decryption was
/// unimplemented and the MHD_PASSWORD flag blocked unconditionally.
///
/// Distinct from [`needs_password`], which asks "is a password needed"
/// with none supplied; this asks "is the password we have any use to the
/// streaming path".
pub fn headers_encrypted_to(path: &std::path::Path, password: Option<&str>) -> bool {
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let size = f.metadata().map(|m| m.len()).unwrap_or(0);
    let mut m = VolumeMapper::with_password(size, password.map(std::sync::Arc::from));
    feed_headers_incrementally(&mut f, size, &mut m);
    matches!(m.blocker, Some(MapBlocker::EncryptedHeaders))
}

// ---------------------------------------------------------------------------
// Multi-volume archive: piece base-offset resolution
// ---------------------------------------------------------------------------

/// Base (inner-file) offsets for every parsed piece, resolved in volume
/// order. A piece's base is only known once every piece of the same file
/// in earlier volumes has a known length - resolution is re-run as
/// volumes parse (cheap: O(total pieces)).
pub struct ArchiveMap {
    /// (volume, entry) → inner-file base offset.
    pub bases: HashMap<(usize, usize), u64>,
    /// A piece's offset was derived from BOTH neighbours and the two
    /// disagreed. Impossible for a healthy set - the headers contradict
    /// themselves - so the caller demotes rather than writing bytes at
    /// an offset it cannot justify.
    pub contradiction: bool,
}

impl ArchiveMap {
    /// `vols[i]` = the mapper for volume i (in .partNN order).
    ///
    /// A split file has AT MOST ONE piece per volume, and its pieces span
    /// CONSECUTIVE volumes - so a continuation's base in volume K is
    /// resolvable as soon as the same file's piece in volume K-1 has been
    /// parsed, even while K-1's later headers (and its end block, which
    /// lives in the volume's LAST article) are still in flight. Waiting
    /// for volume completeness instead stalled resolution behind every
    /// volume's final article and blew the holds cap on a 79-volume 35 GB
    /// set (holds grew at line rate for the whole download).
    pub fn resolve(vols: &[&VolumeMapper]) -> ArchiveMap {
        let indexed: Vec<(u64, &VolumeMapper)> = vols
            .iter()
            .enumerate()
            .map(|(i, m)| (i as u64, *m))
            .collect();
        Self::resolve_indexed(&indexed)
    }

    /// Base offsets for every parsed piece, from volumes that need NOT be
    /// a consecutive run - each carries its own volume index and
    /// adjacency is decided per neighbouring pair.
    ///
    /// Resolution is a propagation from two kinds of certain seed:
    ///
    /// - a piece with `!split_before` STARTS its file, so its base is 0;
    /// - a piece with `split_before && !split_after` ENDS its file, so its
    ///   base is `unpacked_size - data_len` - a fact from that one
    ///   volume's own header, needing no other volume at all.
    ///
    /// From any seeded piece the offsets walk BOTH ways along consecutive
    /// parsed volumes carrying the same inner file: forward by adding the
    /// earlier piece's length, backward by subtracting the earlier
    /// piece's own. Repeat to a fixpoint.
    ///
    /// The tail seed is what makes multi-file (season-pack) sets place
    /// under a partial or out-of-order arrival: instead of one run
    /// reaching back to volume 0, each inner file needs only a run
    /// containing its own first or last volume. Forward-only resolution
    /// from volume 0 was why an obfuscated season pack could hold
    /// unplaceable bytes until the whole set had parsed.
    ///
    /// Every base here is DERIVED from a header that actually parsed, so
    /// unlike the arithmetic gate there is no premise to be wrong about
    /// and nothing to withdraw later. A piece reached from both
    /// directions must agree; disagreement means self-contradictory
    /// headers and sets [`ArchiveMap::contradiction`].
    pub fn resolve_indexed(vols: &[(u64, &VolumeMapper)]) -> ArchiveMap {
        let mut bases: HashMap<(usize, usize), u64> = HashMap::new();
        let mut contradiction = false;

        // 1. Seeds.
        for (pos, (_, m)) in vols.iter().enumerate() {
            for (ei, e) in m.entries.iter().enumerate() {
                if e.is_dir {
                    continue;
                }
                if !e.split_before {
                    bases.insert((pos, ei), 0);
                } else if !e.split_after && tail_anchorable(e) {
                    // Checked: a piece longer than the file it ends is a
                    // broken header, not a base.
                    if let Some(b) = e.unpacked_size.checked_sub(e.data_len) {
                        bases.insert((pos, ei), b);
                    }
                }
            }
        }

        // 2. Links between adjacent parsed volumes that continue one
        //    inner file. A split file has at most ONE piece per volume;
        //    a volume naming the same file twice is malformed, so that
        //    name simply does not link (never a guess).
        let mut links: Vec<(usize, usize, usize, usize, u64)> = Vec::new();
        for i in 0..vols.len().saturating_sub(1) {
            if vols[i + 1].0 != vols[i].0 + 1 {
                continue; // not adjacent volumes - no chain across a gap
            }
            let (ma, mb) = (vols[i].1, vols[i + 1].1);
            for (ea_i, ea) in ma.entries.iter().enumerate() {
                if ea.is_dir || !ea.split_after {
                    continue;
                }
                let once_a = ma
                    .entries
                    .iter()
                    .filter(|x| !x.is_dir && x.name == ea.name)
                    .count();
                if once_a != 1 {
                    continue;
                }
                let Some((eb_i, eb)) = mb
                    .entries
                    .iter()
                    .enumerate()
                    .find(|(_, x)| !x.is_dir && x.name == ea.name)
                else {
                    continue;
                };
                if !eb.split_before {
                    continue;
                }
                let once_b = mb
                    .entries
                    .iter()
                    .filter(|x| !x.is_dir && x.name == ea.name)
                    .count();
                if once_b != 1 {
                    continue;
                }
                links.push((i, ea_i, i + 1, eb_i, ea.data_len));
            }
        }

        // 3. Propagate to a fixpoint. Sweeping forward then backward in
        //    volume order carries a seed the length of its chain per
        //    iteration, so this converges in a couple of passes rather
        //    than one pass per volume.
        for _ in 0..vols.len().max(1) {
            let mut changed = false;
            let mut step = |from: Option<u64>,
                            to_key: (usize, usize),
                            bases: &mut HashMap<(usize, usize), u64>,
                            contradiction: &mut bool| {
                let Some(want) = from else { return };
                match bases.get(&to_key) {
                    None => {
                        bases.insert(to_key, want);
                        changed = true;
                    }
                    Some(&have) if have != want => *contradiction = true,
                    _ => {}
                }
            };
            for &(pa, ea, pb, eb, len) in links.iter() {
                let a = bases.get(&(pa, ea)).copied();
                step(
                    a.and_then(|b| b.checked_add(len)),
                    (pb, eb),
                    &mut bases,
                    &mut contradiction,
                );
            }
            for &(pa, ea, pb, eb, len) in links.iter().rev() {
                let b = bases.get(&(pb, eb)).copied();
                if let Some(bv) = b {
                    match bv.checked_sub(len) {
                        Some(want) => step(Some(want), (pa, ea), &mut bases, &mut contradiction),
                        // The earlier piece would start before the file
                        // does: the two headers cannot both be true.
                        None => contradiction = true,
                    }
                }
            }
            if !changed {
                break;
            }
        }
        ArchiveMap {
            bases,
            contradiction,
        }
    }

    /// Arithmetic placement for uniform single-file RAR5 STORE sets:
    /// when every parsed volume carries exactly one piece of one file
    /// and the volume geometry is consistent, volume N's piece base is
    /// computable from N and the geometry alone - every volume is
    /// placeable the moment ITS OWN headers parse, under any arrival
    /// order. This is the obfuscated-remux headline shape that chain
    /// resolution (above) demotes when arrival order keeps the
    /// consecutive-from-0 run short.
    ///
    /// The geometry is NOT "uniform data_len" (the trap that demoted the
    /// first live set this ran against): real archivers keep the VOLUME
    /// size constant, so the data area shrinks by a byte wherever the
    /// main header's volume-number vint grows - at volume 128, again at
    /// 16384 - and volume 0, whose number field is absent entirely,
    /// carries one byte MORE than volumes 1..127. The true invariants,
    /// validated against every parsed volume:
    ///
    ///   data_off(k) == off_base + volnum_field_len(k)
    ///   data_off(k) + data_len(k) == data_end          (non-final k)
    ///
    /// from which any volume's base follows in closed form:
    ///
    ///   D = data_end - off_base                      (= volume 0's dl)
    ///   base(N) = sum of dl(k) for k < N = N*D - S(N)
    ///
    /// with S(N) the total volume-number field bytes across volumes
    /// 0..N-1 ([`volnum_field_bytes_before`]). A set whose non-final
    /// pieces all share one data_len regardless of header size (some
    /// custom packers) does NOT fit this model and stays on the chain
    /// path - business as usual, never a demote.
    ///
    /// `vols` is every parsed mapper of the group, in ANY order. The
    /// distinction between the two failure modes matters to the caller:
    /// [`ArithGate::Shape`] says "not this kind of set" (multi-file,
    /// RAR4, encrypted, unnumbered...) - chain territory - while
    /// [`ArithGate::Numbers`] says the set LOOKS like this shape but its
    /// numbers contradict the premise, so any bytes placed under it are
    /// suspect.
    pub fn resolve_arithmetic(vols: &[&VolumeMapper]) -> ArithGate {
        use ArithGate::{Numbers, Shape};
        if vols.is_empty() {
            return Shape;
        }
        let mut geom: Option<(u64, u64)> = None; // (off_base, data_end) from non-finals
        let mut fin: Option<(u64, u64, u64)> = None; // final (volnum, data_len, data_off)
        let mut total: Option<u64> = None;
        let mut name: Option<&str> = None;
        let mut seen: HashSet<u64> = HashSet::with_capacity(vols.len());
        // Did a parsed volume 0 actually START this file? (Half of the
        // premise proof below.)
        let mut starts_at_zero = false;
        for m in vols {
            if m.version != Some(RarVersion::V5) || m.blocker.is_some() {
                return Shape;
            }
            let Some(vn) = m.volume_number else {
                return Shape;
            };
            let [e] = m.entries.as_slice() else {
                return Shape;
            };
            // Encrypted entries (with OR without a usable password) stay
            // on the chain path - the in-stream decrypt machinery was
            // built and verified against chained placement.
            if e.is_dir
                || e.encrypted
                || e.crypt.is_some()
                || e.size_unknown
                || !matches!(e.method, Method::Store)
                || e.unpacked_size == 0
            {
                return Shape;
            }
            match &name {
                None => name = Some(e.name.as_str()),
                Some(n) if *n == e.name => {}
                Some(_) => return Shape,
            }
            // A piece that STARTS anywhere but volume 0 means a second
            // file begins mid-set: multi-file territory, the chain's job.
            if vn > 0 && !e.split_before {
                return Shape;
            }
            match total {
                None => total = Some(e.unpacked_size),
                Some(t) if t == e.unpacked_size => {}
                Some(_) => return Numbers,
            }
            if vn == 0 && e.split_before {
                return Numbers; // a continuation at the archive head
            }
            if vn == 0 {
                starts_at_zero = true;
            }
            if !seen.insert(vn) {
                return Numbers; // duplicate volume number
            }
            // Header-base consistency: this volume's data offset must sit
            // exactly volnum_field_len(vn) past the shared base.
            let Some(off_base) = e.data_off.checked_sub(volnum_field_len(vn)) else {
                return Numbers;
            };
            if e.split_after {
                if e.data_len == 0 {
                    return Shape;
                }
                let Some(dend) = e.data_off.checked_add(e.data_len) else {
                    return Numbers;
                };
                match geom {
                    None => geom = Some((off_base, dend)),
                    Some((ob, de)) if ob == off_base && de == dend => {}
                    Some(_) => return Numbers, // volume geometry contradicts
                }
            } else {
                if let Some(&(ob, _)) = geom.as_ref()
                    && ob != off_base
                {
                    return Numbers;
                }
                if fin.replace((vn, e.data_len, e.data_off)).is_some() {
                    return Numbers; // two declared-final pieces of one file
                }
            }
        }
        // A final parsed before any non-final: its off_base still has to
        // agree once geometry is known - re-check it here (the loop only
        // compared when geom was already set).
        if let (Some((fvn, _, foff)), Some((ob, _))) = (fin, geom)
            && foff.checked_sub(volnum_field_len(fvn)) != Some(ob)
        {
            return Numbers;
        }
        let total = total.unwrap();
        // Per-volume capacity D (volume 0's data_len): from geometry, or
        // derived from the final piece when only IT has parsed - the
        // premise fixes base(fvn) == total - fdl, so D must divide out
        // exactly.
        let d = match (geom, fin) {
            (Some((ob, de)), _) => {
                let Some(d) = de.checked_sub(ob) else {
                    return Numbers;
                };
                d
            }
            (None, Some((fvn, fdl, _))) if fvn > 0 => {
                let Some(head) = total.checked_sub(fdl) else {
                    return Numbers;
                };
                let Some(s) = volnum_field_bytes_before(fvn) else {
                    return Numbers;
                };
                let Some(num) = head.checked_add(s) else {
                    return Numbers;
                };
                if num % fvn != 0 {
                    return Numbers;
                }
                let d = num / fvn;
                if d == 0 || fdl > d {
                    return Numbers;
                }
                d
            }
            // Only a volnum-0 piece parsed; D is unused below.
            _ => 0,
        };
        // PROOF that the premise holds, before a single byte is placed on
        // it. The premise is "this file begins at volume 0", and headers
        // establish it exactly two ways: a parsed volume 0 whose piece
        // STARTS the file, or the closure identity against a parsed FINAL
        // piece (base(fvn) == total - fdl). Without one, this is not a
        // shape we may place - and that is `Shape`, not `Numbers`.
        //
        // Both halves matter. Refusing to bet without proof is what stops
        // a season pack's continuation-only group - locally uniform,
        // single-name, single-entry, but with absolute volume numbers and
        // a file that starts far into the set - from being placed at
        // offsets that are simply wrong. And reporting it as a different
        // shape rather than a contradiction is what keeps it streaming:
        // chain resolution places it correctly, so there is nothing to
        // demote.
        //
        // The proof costs nothing against the alternative: the tail seed
        // that chain resolution needs is the SAME fact as closure proof
        // here, so a set that could have been placed eagerly can be
        // placed by propagation at the same moment.
        //
        // The distinction is load-bearing. A group holding only the
        // CONTINUATION volumes of a middle file - a season pack before
        // its per-file groups merge - looks locally uniform, single-name
        // and single-entry, and satisfies every per-volume rule above.
        // What it cannot satisfy is the premise that its file begins at
        // volume 0: its volume numbers are absolute while its file starts
        // far into the set, so the closure identity fails. Reporting that
        // as a contradiction demoted healthy season packs (the whole
        // shape this path exists to keep streaming); reporting it as a
        // different shape costs nothing, because the chain handles it.
        let mut proven = starts_at_zero;
        if let Some((fvn, fdl, _)) = fin {
            if seen.iter().any(|&v| v > fvn) {
                return Shape; // pieces past the declared last volume
            }
            let Some(head) = total.checked_sub(fdl) else {
                return Shape;
            };
            if fvn == 0 {
                if head != 0 {
                    return Shape; // an unsplit volume must hold the whole file
                }
            } else if arith_base(fvn, d) != Some(head) || fdl > d {
                return Shape; // the set does not close from volume 0
            }
            proven = true;
        }
        if !proven {
            return Shape;
        }
        let mut bases = Vec::with_capacity(vols.len());
        for m in vols {
            let e = &m.entries[0];
            let vn = m.volume_number.unwrap();
            let base = if !e.split_before {
                0
            } else if !e.split_after {
                total - e.data_len // final piece; fits by checked_sub above
            } else {
                match arith_base(vn, d) {
                    Some(b) => b,
                    None => return Numbers,
                }
            };
            // A piece landing outside the declared file means the
            // premise (this file starts at volume 0, uniform capacity)
            // does not describe this set - most often a continuation-only
            // group whose absolute volume numbers run far past its own
            // file. Not a contradiction: hand it to the chain.
            if base.checked_add(e.data_len).is_none_or(|end| end > total) {
                return Shape;
            }
            bases.push(base);
        }
        // Volume numbers are distinct and all <= fvn, so a count of
        // fvn + 1 means exactly {0..=fvn}: the complete set, closed.
        // `saturating_add`, like every other arithmetic in this function:
        // `fvn` is a header vint, and a crafted volume number of u64::MAX
        // satisfies every guard above (a zero-length FINAL piece is accepted
        // - the data_len reject lives in the split_after arm). Release wraps
        // to 0 and answers "not closed", which is safe; debug and test builds
        // panicked here while holding the routing lock, poisoning it for the
        // rest of the job.
        let closed = fin.is_some_and(|(fvn, _, _)| seen.len() as u64 == fvn.saturating_add(1));
        ArithGate::Place { bases, closed }
    }
}

/// Bytes the RAR5 main header spends on the volume-number field for
/// volume `vn`: absent on volume 0 (MHD_VOLUME implies "first"), else
/// the vint length of the number - 1 byte through volume 127, 2 through
/// 16383, and so on.
fn volnum_field_len(vn: u64) -> u64 {
    if vn == 0 {
        return 0;
    }
    let mut n = vn;
    let mut l = 0u64;
    while n > 0 {
        n >>= 7;
        l += 1;
    }
    l
}

/// S(N): total volume-number field bytes across volumes 0..N-1 - the
/// closed-form band sum behind `base(N) = N*D - S(N)`.
fn volnum_field_bytes_before(n: u64) -> Option<u64> {
    let mut s = 0u64;
    let mut band_start = 1u64; // volume 0 contributes nothing
    let mut len = 1u64;
    while band_start < n {
        let band_end = if len >= 10 {
            u64::MAX
        } else {
            (1u64 << (7 * len)) - 1
        };
        let hi = band_end.min(n - 1);
        s = s.checked_add((hi - band_start + 1).checked_mul(len)?)?;
        if band_end >= n.saturating_sub(1) {
            break;
        }
        band_start = band_end + 1;
        len += 1;
    }
    Some(s)
}

/// base(N) = N*D - S(N): the inner-file offset where volume N's piece
/// starts, under the constant-volume-size geometry. None on overflow or
/// an impossible (S > N*D) combination - hostile headers fail closed.
fn arith_base(n: u64, d: u64) -> Option<u64> {
    n.checked_mul(d)?.checked_sub(volnum_field_bytes_before(n)?)
}

/// May this piece's base be derived from `unpacked_size - data_len`?
///
/// Only for a plain stored, unencrypted member. For a COMPRESSED entry
/// `data_len` is the packed length while `unpacked_size` is the unpacked
/// one, so the subtraction is meaningless. For an ENCRYPTED one the
/// pieces tile block-padded CIPHER space whose total is `sum(data_len)`
/// and can exceed `unpacked_size` (the finish pass truncates to it), so
/// the same subtraction is wrong - those keep resolving by summing
/// lengths forward, which is correct in cipher space.
fn tail_anchorable(e: &FileEntry) -> bool {
    matches!(e.method, Method::Store)
        && !e.encrypted
        && e.crypt.is_none()
        && !e.size_unknown
        && !e.is_dir
        && e.data_len <= e.unpacked_size
}

/// Outcome of [`ArchiveMap::resolve_arithmetic`].
pub enum ArithGate {
    /// Gate passed: `bases[i]` is the inner-file base offset of
    /// `vols[i]`'s single entry. `closed` means the parsed volumes form
    /// the complete set 0..=last, ending in the declared final piece -
    /// the premise is proven, not just unrefuted.
    Place { bases: Vec<u64>, closed: bool },
    /// Not this shape at all - chain resolution territory.
    Shape,
    /// The shape matched but the numbers contradict the uniform
    /// single-file premise.
    Numbers,
}

// ---------------------------------------------------------------------------
// Fixture writers: minimal store-mode RAR5 + RAR4 encoders. Used by unit
// tests and the end-to-end chaos suite (and eventually by a posting tool).
// ---------------------------------------------------------------------------

#[doc(hidden)]
pub mod fixtures;

// The RAR4 header-framing tests - a child module (the par2repair.rs
// pattern) so rar.rs stays under the size-gate ceiling while `super::*`
// keeps the private parser reachable.
#[cfg(test)]
mod v4_header_tests;

// RAR4 mapping against bytes RARLAB's own archiver wrote, which is a
// different claim from `tests.rs`'s RAR4 half: those fixtures came out
// of the vendored writer, so they can only exercise fields we already
// know how to emit. Same child-module reason as v4_header_tests.
#[cfg(test)]
mod archiver_tests;

#[cfg(test)]
mod tests;
