//! yEnc body-layer encryption (Tensai75 yenc-encryption-standards,
//! "yEnc Body Encryption Standard" v0.3) - decode-side spike plus our own
//! encoder half, both OFF unless `NZBFAST_YENC_CRYPT=1`.
//!
//! The DRAFTS carry no vectors, but reference implementations exist -
//! found 31 Aug 2026, a day after two searches said otherwise:
//! github.com/Tensai75/go-yenc-body-encryption and
//! go-yenc-header-encryption (they are not linked from the standards
//! repo, which is how they were missed). Where the draft text is
//! ambiguous, THE REFERENCE CODE is the convention this module
//! follows, verified by running it against these pinned inputs:
//!   - segmentIndex serializes into the body nonce HMAC as u32
//!     LITTLE-endian (`binary.LittleEndian` in the reference; the
//!     draft says only "|| segmentIndex", and note the CONTROL tweak
//!     below is big-endian in the same author's other package - an
//!     inconsistency reported upstream, matched here as-is).
//!   - Argon2id "memory=64MB" means m = 65536 KiB, version 1.3 (the
//!     reference calls Go x/crypto `argon2.IDKey`, which is exactly
//!     that).
//!   - AAD is empty (the reference passes nil).
//!   - The `=yencryption` line is emitted directly after `=ybegin`;
//!     on decode it is accepted anywhere in the block.
//!
//! The control-lines (FF1) half is implemented below under FURTHER
//! declared conventions, because the draft's own text cannot be
//! followed as written - its lineIndex definition and worked example
//! count ALL physical lines (the footer of a 4-line block is
//! lineIndex 4) while its encryption step text increments only on `=y`
//! lines (same footer would be 2). Two of its three witnesses agree,
//! the REFERENCE implementation (go-yenc-header-encryption) agrees
//! with them - verified byte-exact against its output, tweak and
//! ciphertext alike - and this implementation matches all three:
//!   - lineIndex IS the physical 1-based line number within the block
//!     (the definition's, worked example's and reference's reading;
//!     the step text is the outlier).
//!   - Alphabet bijection: the 253 byte values 0x01-0xFF minus CR/LF
//!     map to numerals 0..252 in ascending byte order (the reference's
//!     alphabet string spells exactly this order out).
//!   - segmentIndex and lineIndex serialize u32 BIG-ENDIAN in the
//!     tweak HMAC (`binary.BigEndian` in the reference - which is the
//!     opposite of its own body package; matched as-is).
//!   - Combined use: body encryption first, control-lines second on
//!     encode (so control-decrypt runs FIRST on decode), and the
//!     `=yencryption` line is a `=y` line counted at its physical
//!     index like any other.
//!   - Detection: an article whose first body line starts `=ybegin` is
//!     never control-decrypted; anything else gets one trial decrypt
//!     of line 1, and only a result starting `=y` commits (the draft's
//!     own probabilistic contract - a false positive is ~253^-2 and
//!     lands on the per-article retry machinery, never on disk).

use crate::nzb::NzbFile;
use crate::sync::MutexExt;
use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use hmac::digest::KeyInit as MacKeyInit;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

/// The one cipher value the draft defines. An unknown cipher on the wire
/// is a refusal (`YencError::BadEncryption`), never a guess.
pub const CIPHER: &str = "XChaCha20-Poly1305";

/// Whether the wire-side spike is on. Read once per process: the e2e rig
/// drives the real binary with per-test env, and in-process unit tests
/// call the flag-free functions below directly, so nothing ever needs to
/// toggle this within one process.
pub fn wire_enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var("NZBFAST_YENC_CRYPT").is_ok_and(|v| v == "1"))
}

/// The parsed `=yencryption` control line: session salt and this
/// segment's Poly1305 tag, both 16 bytes hex on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncHeader {
    pub salt: [u8; 16],
    pub tag: [u8; 16],
}

impl EncHeader {
    /// Parse the fields after the `=yencryption ` keyword (both decoders
    /// hand the same tail here - ONE parser, or the oracle and the SIMD
    /// path drift). Refuses an unknown cipher and any missing/short
    /// field: a captured-but-wrong header would hand ciphertext to the
    /// verifier as if it were plaintext.
    pub fn parse_fields(tail: &[u8]) -> Option<EncHeader> {
        let mut cipher_ok = false;
        let mut salt = None;
        let mut tag = None;
        for word in tail.split(|&b| b == b' ' || b == b'\t') {
            if let Some(v) = word.strip_prefix(b"cipher=") {
                cipher_ok = v == CIPHER.as_bytes();
            } else if let Some(v) = word.strip_prefix(b"salt=") {
                salt = hex16(v);
            } else if let Some(v) = word.strip_prefix(b"tag=") {
                tag = hex16(v);
            }
        }
        match (cipher_ok, salt, tag) {
            (true, Some(salt), Some(tag)) => Some(EncHeader { salt, tag }),
            _ => None,
        }
    }
}

/// 32 lowercase-or-uppercase hex chars -> 16 bytes.
fn hex16(v: &[u8]) -> Option<[u8; 16]> {
    if v.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, pair) in v.chunks(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

/// The `=yencryption` control line our encoder half emits (no trailing
/// line ending; the caller frames it).
pub fn control_line(salt: &[u8; 16], tag: &[u8; 16]) -> String {
    format!(
        "=yencryption cipher={CIPHER} salt={} tag={}",
        hex32(salt),
        hex32(tag)
    )
}

fn hex32(b: &[u8; 16]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Argon2id(password, salt, time=1, memory=64MB, threads=4, 256-bit).
/// ~25 ms on the dev box - once per (password, salt), which is once per
/// job in practice (the salt is per upload session).
pub fn derive_key(password: &str, salt: &[u8; 16]) -> [u8; 32] {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(65536, 1, 4, Some(32)).expect("fixed Argon2 parameters are in range");
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    a.hash_password_into(password.as_bytes(), salt, &mut out)
        .expect("fixed-parameter Argon2 cannot fail on any password/salt");
    out
}

/// The draft's per-segment nonce: HMAC-SHA256 of "yenc-body nonce"
/// followed by segmentIndex, truncated to 24 bytes, keyed with the
/// session key. segmentIndex serializes as u32 LITTLE-endian, matching
/// the author's reference implementation (go-yenc-body-encryption's
/// `DeriveNonce` spells `binary.LittleEndian` out) - see the module
/// header for why that outranks the tidier big-endian this module
/// declared before the reference was found. Public so the vector-corpus
/// writer (`nzbfast yenc-vectors`) can publish the intermediate values
/// a future implementer validates against.
pub fn nonce_for(key: &[u8; 32], segment_index: u32) -> [u8; 24] {
    let mut mac =
        <Hmac<Sha256> as MacKeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(b"yenc-body nonce");
    mac.update(&segment_index.to_le_bytes());
    let full = mac.finalize().into_bytes();
    let mut n = [0u8; 24];
    n.copy_from_slice(&full[..24]);
    n
}

/// Decrypt one segment's decoded bytes in place, verifying the Poly1305
/// tag from its `=yencryption` line. False = authentication failed (the
/// buffer is left as whatever the failed pass produced - callers treat
/// the article as corrupt and never read the bytes).
#[must_use]
pub fn decrypt_segment(key: &[u8; 32], segment_index: u32, tag: &[u8; 16], buf: &mut [u8]) -> bool {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = nonce_for(key, segment_index);
    cipher
        .decrypt_inout_detached((&nonce).into(), b"", buf.into(), &(*tag).into())
        .is_ok()
}

/// Encrypt one segment's plaintext in place, returning its tag - the
/// encoder half, used by the mock/post fixture path. There is no
/// reference implementation to test against, so this is also what the
/// decode side is validated against (plus the pinned vector below).
pub fn encrypt_segment(key: &[u8; 32], segment_index: u32, buf: &mut [u8]) -> [u8; 16] {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = nonce_for(key, segment_index);
    let tag = cipher
        .encrypt_inout_detached((&nonce).into(), b"", buf.into())
        .expect("XChaCha20 in-place encrypt is infallible for in-memory buffers");
    tag.into()
}

/// The draft's segmentIndex is continuous across ALL files of the upload
/// session, in `[n/total]` subject order. This computes each file's FIRST
/// index (1-based) from the NZB, or None when the NZB cannot support it:
/// any file missing the prefix (unless the NZB is a single file, whose
/// base is trivially 1), or duplicate file numbers. A file's segment
/// count is the larger of its highest segment number and its segment
/// list length, so an NZB that lost a segment row still indexes the
/// files after it correctly.
pub fn file_seg_bases(files: &[NzbFile]) -> Option<Vec<u32>> {
    if files.len() == 1 {
        return Some(vec![1]);
    }
    let mut numbered: Vec<(u32, usize)> = Vec::with_capacity(files.len());
    for (fi, f) in files.iter().enumerate() {
        let (n, _total) = subject_file_number(&f.subject)?;
        numbered.push((n, fi));
    }
    numbered.sort_unstable();
    if numbered.windows(2).any(|w| w[0].0 == w[1].0) {
        return None;
    }
    let mut bases = vec![0u32; files.len()];
    let mut next: u32 = 1;
    for &(_, fi) in &numbered {
        bases[fi] = next;
        let f = &files[fi];
        let count = f
            .segments
            .iter()
            .map(|s| s.number)
            .max()
            .unwrap_or(0)
            .max(f.segments.len() as u32);
        next = next.checked_add(count)?;
    }
    Some(bases)
}

/// Leading `[n/m]` file-number prefix the draft REQUIRES on every
/// subject (its Section 8). Returns (n, m); n must be 1..=m.
pub fn subject_file_number(subject: &str) -> Option<(u32, u32)> {
    let rest = subject.trim_start().strip_prefix('[')?;
    let close = rest.find(']')?;
    let inner = &rest[..close];
    let (n, m) = inner.split_once('/')?;
    let n: u32 = n.trim().parse().ok()?;
    let m: u32 = m.trim().parse().ok()?;
    if n >= 1 && n <= m { Some((n, m)) } else { None }
}

/// Everything the decode fleet needs to decrypt a job's segments:
/// the job password, each slot's first segmentIndex, and the derived-key
/// cache (the salt is per-session so this holds one entry in practice,
/// but a hostile post can vary it per segment and must not re-run Argon2
/// into a different answer than the honest path - so it is a map).
pub struct JobCrypt {
    password: String,
    /// Per SLOT (not per NZB file): the caller maps slot -> file.
    slot_base: Vec<u32>,
    /// Unbracketed message-id -> session segmentIndex, over EVERY file
    /// of the NZB. The control-lines path needs the index BEFORE any
    /// yEnc parse (there is no `=ypart` to read on an FF1 article), and
    /// the message-id is the one thing the fetch loop knows pre-decode.
    seg_by_id: HashMap<String, u32>,
    keys: Mutex<HashMap<[u8; 16], Arc<[u8; 32]>>>,
    /// FF1 session contexts per control salt - same hostile-post
    /// reasoning as `keys`: one entry in practice, a map for safety.
    controls: Mutex<HashMap<[u8; 16], Arc<ControlCrypt>>>,
}

impl JobCrypt {
    /// Build the job context, or None when the spike is off, the job has
    /// no password, or the NZB cannot carry the draft's continuous
    /// segmentIndex (see [`file_seg_bases`]). None simply means every
    /// `=yencryption` article of this job fails decode with
    /// `EncryptedUnsupported` - the honest outcome, and the same shape a
    /// missing RAR password already lands on.
    pub fn for_job(
        files: &[NzbFile],
        slot_file: &[usize],
        password: Option<&str>,
    ) -> Option<Arc<JobCrypt>> {
        if !wire_enabled() {
            return None;
        }
        let password = password?.to_string();
        let bases = file_seg_bases(files)?;
        let slot_base = slot_file.iter().map(|&fi| bases[fi]).collect();
        let mut seg_by_id = HashMap::new();
        for (fi, f) in files.iter().enumerate() {
            for s in &f.segments {
                seg_by_id.insert(s.message_id.clone(), bases[fi] + s.number.saturating_sub(1));
            }
        }
        Some(Arc::new(JobCrypt {
            password,
            slot_base,
            seg_by_id,
            keys: Mutex::new(HashMap::new()),
            controls: Mutex::new(HashMap::new()),
        }))
    }

    /// The session segmentIndex of one article, resolved by message-id
    /// (bracketed or bare - the pool's ids carry `<>`, the NZB's do
    /// not). None = an id this NZB never declared.
    pub fn segment_index_for_id(&self, id: &str) -> Option<u32> {
        let bare = id
            .strip_prefix('<')
            .and_then(|s| s.strip_suffix('>'))
            .unwrap_or(id);
        self.seg_by_id.get(bare).copied()
    }

    /// Derive-or-cache the FF1 session context for a control salt.
    fn control_for(&self, salt: &[u8; 16]) -> Arc<ControlCrypt> {
        if let Some(c) = self.controls.lock_ok().get(salt) {
            return c.clone();
        }
        let master = self.key_for(salt);
        let built = Arc::new(ControlCrypt::new(&master));
        self.controls.lock_ok().insert(*salt, built.clone());
        built
    }

    /// Control-lines detection plus whole-block decrypt for one article
    /// body. None = not control-encrypted (or not decryptable by this
    /// job's password), and the caller proceeds with the original
    /// bytes; Some = the block with every control line restored, ready
    /// for the ordinary yEnc decode (and the body-decrypt after it,
    /// when the restored block carries `=yencryption`).
    pub fn control_decrypt_article(&self, id: &str, block: &[u8]) -> Option<Vec<u8>> {
        let seg = self.segment_index_for_id(id)?;
        let salt = control_block_salt(block)?;
        let cc = self.control_for(&salt);
        control_decrypt_block(&cc, seg, block)
    }

    /// This slot's article with yEnc part number `part` (None = a
    /// single-part post = part 1) has this session-wide segmentIndex.
    pub fn segment_index(&self, sidx: usize, part: Option<u32>) -> u32 {
        let base = self.slot_base.get(sidx).copied().unwrap_or(1);
        base.saturating_add(part.unwrap_or(1).saturating_sub(1))
    }

    /// Derive-or-cache the key for a session salt (~25 ms first time).
    pub fn key_for(&self, salt: &[u8; 16]) -> Arc<[u8; 32]> {
        if let Some(k) = self.keys.lock_ok().get(salt) {
            return k.clone();
        }
        // Derive OUTSIDE the lock: Argon2 at 64 MiB is tens of ms and
        // every decode thread would queue behind it. Two threads racing
        // the same salt derive the same bytes, so last-write-wins is
        // correct.
        let derived = Arc::new(derive_key(&self.password, salt));
        self.keys.lock_ok().insert(*salt, derived.clone());
        derived
    }
}

// ---------------------------------------------------------------------
// Control-lines standard (FF1) - the draft's second half, under the
// declared conventions in the module header.

/// The draft's alphabet size: bytes 0x01-0xFF minus CR and LF.
pub const CONTROL_RADIX: u32 = 253;

/// Longest line the control-lines pass will run FF1 over. Every control
/// line the draft defines (`=ybegin`, `=ypart`, `=yend`, `=yencryption`)
/// is under 200 bytes, so this is two orders of magnitude of headroom.
/// The bound exists because FF1's radix-253 digit conversions are
/// QUADRATIC in the line length (num-bigint's `from_radix_digits_be` is
/// a per-chunk scalar multiply-add over a growing limb vector, with no
/// divide-and-conquer) and it also builds `radix^n`, `radix^u` and
/// `radix^v` BigUints of that order before the first round runs - while
/// a body line is bounded only by `MAX_MULTILINE_BYTES` (256 MiB),
/// nothing between the socket and the decoder caps a single LINE, and
/// the line-1 trial decrypt happens before any `=y` commit check. An
/// unbounded trial decrypt is therefore tens of seconds of decode-thread
/// CPU, plus a matching allocation, per hostile article.
const MAX_CONTROL_LINE: usize = 4096;

/// Byte -> numeral under the declared ascending bijection. None = the
/// byte is outside the alphabet (NUL, CR, LF), which on the decode side
/// means "this line cannot be a control-encrypted line".
fn alpha_digit(b: u8) -> Option<u8> {
    match b {
        0 | b'\n' | b'\r' => None,
        1..=9 => Some(b - 1),
        0x0B | 0x0C => Some(b - 2),
        _ => Some(b - 3),
    }
}

/// Numeral -> byte, the exact inverse of [`alpha_digit`].
fn alpha_byte(d: u8) -> u8 {
    match d {
        0..=8 => d + 1,
        9 | 10 => d + 2,
        _ => d + 3,
    }
}

fn to_digits(bytes: &[u8]) -> Option<Vec<u8>> {
    bytes.iter().map(|&b| alpha_digit(b)).collect()
}

fn from_digits(digits: &[u8]) -> Vec<u8> {
    digits.iter().map(|&d| alpha_byte(d)).collect()
}

/// Physical lines of an article body: (start, content_end, line_end)
/// offsets, content excluding the CR?LF terminator and line_end
/// including it. A final fragment without a terminator is a line; the
/// empty tail after a final LF is not - both halves of the wire format
/// split this same way, which is what makes lineIndex well-defined.
fn physical_lines(block: &[u8]) -> Vec<(usize, usize, usize)> {
    let mut out = Vec::new();
    let mut start = 0;
    while start < block.len() {
        let (content_end, line_end) = match block[start..].iter().position(|&b| b == b'\n') {
            Some(rel) => {
                let le = start + rel + 1;
                let ce = if rel > 0 && block[start + rel - 1] == b'\r' {
                    start + rel - 1
                } else {
                    start + rel
                };
                (ce, le)
            }
            None => (block.len(), block.len()),
        };
        out.push((start, content_end, line_end));
        start = line_end;
    }
    out
}

/// One session's FF1 context: the master key (Argon2id of password and
/// the salt the first line carries) plus the AES-256 FF1 instance keyed
/// with the draft's derived encKey.
pub struct ControlCrypt {
    master: [u8; 32],
    ff1: crate::ff1::Ff1,
}

impl ControlCrypt {
    /// Derive encKey = HMAC-SHA256(master, "yenc-control key") and key
    /// FF1 with it. The master stays for the per-line tweak HMAC - the
    /// draft keys the two differently on purpose.
    pub fn new(master: &[u8; 32]) -> ControlCrypt {
        let mut mac = <Hmac<Sha256> as MacKeyInit>::new_from_slice(master)
            .expect("HMAC accepts any key length");
        mac.update(b"yenc-control key");
        let enc_key: [u8; 32] = mac.finalize().into_bytes().into();
        ControlCrypt {
            master: *master,
            ff1: crate::ff1::Ff1::new(&enc_key, CONTROL_RADIX),
        }
    }

    /// The draft's per-line tweak: HMAC-SHA256 of "yenc-control tweak"
    /// then segmentIndex then lineIndex, truncated to 8 bytes, keyed
    /// with the MASTER key. Both indices u32 big-endian (declared).
    fn tweak(&self, segment_index: u32, line_index: u32) -> [u8; 8] {
        let mut mac = <Hmac<Sha256> as MacKeyInit>::new_from_slice(&self.master)
            .expect("HMAC accepts any key length");
        mac.update(b"yenc-control tweak");
        mac.update(&segment_index.to_be_bytes());
        mac.update(&line_index.to_be_bytes());
        let full = mac.finalize().into_bytes();
        let mut t = [0u8; 8];
        t.copy_from_slice(&full[..8]);
        t
    }

    /// Encrypt one line's content (no terminators). None = a byte
    /// outside the alphabet, a line too short for FF1's domain, or a
    /// line past [`MAX_CONTROL_LINE`] (the encoder half refuses the same
    /// lengths as the decoder half, which is what keeps the round-trip
    /// pins honest).
    pub fn encrypt_line(&self, seg: u32, line_index: u32, content: &[u8]) -> Option<Vec<u8>> {
        if content.len() > MAX_CONTROL_LINE {
            return None;
        }
        let digits = to_digits(content)?;
        let ct = self
            .ff1
            .encrypt(&self.tweak(seg, line_index), &digits)
            .ok()?;
        Some(from_digits(&ct))
    }

    /// Decrypt one line's content - the inverse of [`Self::encrypt_line`].
    /// This is the ONLY entry to FF1 on the decode side, so the
    /// [`MAX_CONTROL_LINE`] refusal here covers all three callers in
    /// [`control_decrypt_block`]: the line-1 trial decrypt, the header
    /// run, and the footer. A None on any of them lands on the path an
    /// article that is simply not control-encrypted already takes.
    pub fn decrypt_line(&self, seg: u32, line_index: u32, content: &[u8]) -> Option<Vec<u8>> {
        if content.len() > MAX_CONTROL_LINE {
            return None;
        }
        let digits = to_digits(content)?;
        let pt = self
            .ff1
            .decrypt(&self.tweak(seg, line_index), &digits)
            .ok()?;
        Some(from_digits(&pt))
    }
}

/// The encoder half: encrypt every `=y` line of a plaintext yEnc block
/// at its physical lineIndex, prepending the session salt to line 1.
/// Line 1 must itself be a control line (`=ybegin` opens every block) -
/// anything else is caller error and refuses, because a block whose
/// salt never got embedded can never be decrypted.
pub fn control_encrypt_block(
    cc: &ControlCrypt,
    salt: &[u8; 16],
    seg: u32,
    block: &[u8],
) -> Option<Vec<u8>> {
    if salt.iter().any(|&b| alpha_digit(b).is_none()) {
        return None;
    }
    let lines = physical_lines(block);
    let first = lines.first()?;
    if !block[first.0..first.1].starts_with(b"=y") {
        return None;
    }
    let mut out = Vec::with_capacity(block.len() + 16);
    for (k, &(s, ce, le)) in lines.iter().enumerate() {
        let content = &block[s..ce];
        if content.starts_with(b"=y") {
            let idx = (k + 1) as u32;
            let enc = cc.encrypt_line(seg, idx, content)?;
            if k == 0 {
                out.extend_from_slice(salt);
            }
            out.extend_from_slice(&enc);
        } else {
            out.extend_from_slice(content);
        }
        out.extend_from_slice(&block[ce..le]);
    }
    Some(out)
}

/// Read the session salt a control-encrypted block carries: the first
/// 16 bytes of line 1. None = too short or a byte outside the alphabet
/// (an unencrypted article can land here; the caller falls through).
pub fn control_block_salt(block: &[u8]) -> Option<[u8; 16]> {
    let lines = physical_lines(block);
    let &(s, ce, _) = lines.first()?;
    let content = &block[s..ce];
    // 16 salt bytes plus at least FF1's 2-digit minimum of ciphertext.
    if content.len() < 18 || content.starts_with(b"=ybegin") {
        return None;
    }
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&content[..16]);
    if salt.iter().any(|&b| alpha_digit(b).is_none()) {
        return None;
    }
    Some(salt)
}

/// The decoder half: trial-decrypt line 1 (past the salt) and commit
/// only on a `=y` result; then restore the header run, leave data lines
/// untouched, and restore the final line as the footer at its physical
/// index. None anywhere = not control-encrypted under this context, or
/// malformed past the point of trust - the caller treats the article
/// exactly as it would have without this pass.
pub fn control_decrypt_block(cc: &ControlCrypt, seg: u32, block: &[u8]) -> Option<Vec<u8>> {
    let lines = physical_lines(block);
    let n = lines.len() as u32;
    let &(s1, ce1, le1) = lines.first()?;
    let c1 = &block[s1..ce1];
    if c1.len() < 18 {
        return None;
    }
    let first = cc.decrypt_line(seg, 1, &c1[16..])?;
    if !first.starts_with(b"=y") {
        return None;
    }
    let mut out = Vec::with_capacity(block.len());
    out.extend_from_slice(&first);
    out.extend_from_slice(&block[ce1..le1]);
    let mut k = 1usize;
    // Header run: every line that trial-decrypts to `=y` is a control
    // line at its physical index. The last line is never consumed here;
    // it is the footer whatever the run did.
    while k + 1 < lines.len() {
        let (s, ce, le) = lines[k];
        match cc.decrypt_line(seg, (k + 1) as u32, &block[s..ce]) {
            Some(dec) if dec.starts_with(b"=y") => {
                out.extend_from_slice(&dec);
                out.extend_from_slice(&block[ce..le]);
                k += 1;
            }
            _ => break,
        }
    }
    // Data lines pass through byte-identical.
    while k + 1 < lines.len() {
        let (s, _, le) = lines[k];
        out.extend_from_slice(&block[s..le]);
        k += 1;
    }
    // Footer: the last physical line, at lineIndex n (the declared
    // all-lines convention - the worked example's `=yend` of a 4-line
    // block decrypts with lineIndex 4, and only 4).
    if k < lines.len() {
        let (s, ce, le) = lines[k];
        let dec = cc.decrypt_line(seg, n, &block[s..ce])?;
        if !dec.starts_with(b"=y") {
            return None;
        }
        out.extend_from_slice(&dec);
        out.extend_from_slice(&block[ce..le]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(number: u32) -> crate::nzb::Segment {
        crate::nzb::Segment {
            number,
            bytes: 1000,
            message_id: format!("id-{number}@t"),
        }
    }

    fn file(subject: &str, nsegs: u32) -> NzbFile {
        NzbFile {
            subject: subject.to_string(),
            poster: String::new(),
            date: 0,
            groups: vec![],
            segments: (1..=nsegs).map(seg).collect(),
            dropped_segments: 0,
        }
    }

    #[test]
    fn a_segment_round_trips_and_the_wrong_password_or_index_refuses() {
        let salt = *b"0123456789abcdef";
        let key = derive_key("test123", &salt);
        let plain = b"the quick brown fox jumps over the lazy dog".to_vec();
        let mut buf = plain.clone();
        let tag = encrypt_segment(&key, 7, &mut buf);
        assert_ne!(buf, plain, "ciphertext must differ from plaintext");
        // Round trip.
        let mut back = buf.clone();
        assert!(decrypt_segment(&key, 7, &tag, &mut back));
        assert_eq!(back, plain);
        // Wrong segment index: different nonce, auth must fail.
        let mut wrong = buf.clone();
        assert!(!decrypt_segment(&key, 8, &tag, &mut wrong));
        // Wrong password: different key, auth must fail.
        let other = derive_key("test124", &salt);
        let mut wrong = buf.clone();
        assert!(!decrypt_segment(&other, 7, &tag, &mut wrong));
        // Corrupt ciphertext: auth must fail.
        let mut corrupt = buf.clone();
        corrupt[0] ^= 1;
        assert!(!decrypt_segment(&key, 7, &tag, &mut corrupt));
    }

    /// Pinned vector: this module is both halves of the wire format, so
    /// a refactor that changes derivation on both sides at once would
    /// still round-trip. The pin is what catches it. Values are THE
    /// REFERENCE IMPLEMENTATION'S OWN OUTPUT (go-yenc-body-encryption
    /// run against these inputs, 31 Aug 2026 - `DeriveKey`,
    /// `DeriveNonce`, `Encrypt` at segmentIndex 1), so this pin IS the
    /// interop claim, not merely a drift alarm. u32 LE segmentIndex,
    /// Argon2id v1.3 m=65536KiB t=1 p=4, empty AAD.
    #[test]
    fn the_derivation_chain_is_pinned_to_the_reference_implementation() {
        let salt = *b"0123456789abcdef";
        let key = derive_key("test123", &salt);
        let nonce = nonce_for(&key, 1);
        let mut buf = b"Hello World.txt!!!".to_vec();
        let tag = encrypt_segment(&key, 1, &mut buf);
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!(
            hex(&key),
            "1492115b8edf2b1330571caa88a868f028745702c8299a0836a201c28a3f610e"
        );
        assert_eq!(
            hex(&nonce),
            "36c051135e6e23ebe29f12716c2754aeafba9a337fa1b6bb"
        );
        assert_eq!(hex(&buf), "fd6e7e9fde2ec2ce25a4a88ca347ec8600a1");
        assert_eq!(hex(&tag), "6a6c96851efa4a41089868d3e16c4559");
    }

    #[test]
    fn the_control_line_round_trips_through_the_parser() {
        let salt = [0x1a; 16];
        let tag = [0xa1; 16];
        let line = control_line(&salt, &tag);
        let tail = line.strip_prefix("=yencryption ").unwrap();
        let h = EncHeader::parse_fields(tail.as_bytes()).unwrap();
        assert_eq!(h.salt, salt);
        assert_eq!(h.tag, tag);
        // Unknown cipher, short salt, missing tag: all refused.
        assert!(EncHeader::parse_fields(b"cipher=AES-GCM salt=00 tag=00").is_none());
        let no_tag = format!("cipher={CIPHER} salt={}", "00".repeat(16));
        assert!(EncHeader::parse_fields(no_tag.as_bytes()).is_none());
    }

    #[test]
    fn seg_bases_follow_subject_order_not_document_order() {
        // Document order 2,1,3 with 3/2/4 segments; subject order wins:
        // file [1/3] gets base 1 (2 segs), [2/3] base 3 (3 segs), [3/3] base 6.
        let files = vec![
            file("[2/3] b.bin", 3),
            file("[1/3] a.bin", 2),
            file("[3/3] c.bin", 4),
        ];
        assert_eq!(file_seg_bases(&files), Some(vec![3, 1, 6]));
        // A single file needs no prefix at all.
        assert_eq!(file_seg_bases(&[file("plain subject", 5)]), Some(vec![1]));
        // Multi-file without prefixes: unsupported, not guessed.
        let bare = vec![file("a", 1), file("b", 1)];
        assert_eq!(file_seg_bases(&bare), None);
        // Duplicate file numbers: refused.
        let dup = vec![file("[1/2] a", 1), file("[1/2] b", 1)];
        assert_eq!(file_seg_bases(&dup), None);
    }

    /// Both decoders, through their `_opts` seams: with the arm on the
    /// `=yencryption` line is captured and the payload is exactly the
    /// ciphertext (round-tripped back to plaintext here); with it off,
    /// the line decodes as payload and the article REFUSES on the =yend
    /// length gate - which is byte-for-byte the pre-spike behavior, and
    /// also the measured answer to the draft's compatibility claim (an
    /// unaware client does NOT "process encrypted blocks normally").
    #[test]
    fn both_decoders_capture_the_encryption_line_and_off_flag_refuses() {
        let salt = *b"0123456789abcdef";
        let key = derive_key("pw", &salt);
        let plain: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let mut articles = std::collections::HashMap::new();
        let segs = crate::mock::make_file_articles_encrypted(
            "f.bin",
            &plain,
            2000,
            "t",
            &key,
            &salt,
            4,
            &mut articles,
        );
        assert_eq!(segs.len(), 3);
        let mut got = vec![0u8; plain.len()];
        for (i, (id, _, part)) in segs.iter().enumerate() {
            let body = &articles[&format!("<{id}>")];
            // SIMD path, arm on.
            let mut out = Vec::new();
            let (m, _integ) =
                crate::yenc_simd::decode_into_integrity_opts(body, &mut out, true, true).unwrap();
            let h = m.encryption.expect("captured");
            assert_eq!(h.salt, salt);
            assert_eq!(m.part, Some(*part));
            // Scalar oracle agrees on capture and payload.
            let (d, _) = crate::yenc::decode_checked_opts(body, true).unwrap();
            assert_eq!(d.encryption, Some(h));
            assert_eq!(d.data, out);
            // The payload is ciphertext; the tag authenticates it under
            // the session-wide segmentIndex (base 4 here).
            assert!(decrypt_segment(&key, 4 + i as u32, &h.tag, &mut out));
            let off = m.offset() as usize;
            got[off..off + out.len()].copy_from_slice(&out);
            // Arm off: the control line decodes as payload bytes and the
            // =yend size gate refuses - on BOTH decoders, identically.
            let mut junk = Vec::new();
            let simd_off =
                crate::yenc_simd::decode_into_integrity_opts(body, &mut junk, true, false);
            let scalar_off = crate::yenc::decode_checked_opts(body, false).map(|_| ());
            assert!(
                matches!(simd_off, Err(crate::yenc::YencError::LengthMismatch { .. })),
                "flag-off must refuse, got {simd_off:?}"
            );
            assert_eq!(scalar_off.unwrap_err(), simd_off.unwrap_err());
        }
        assert_eq!(got, plain, "assembled plaintext must round-trip");
    }

    #[test]
    fn a_malformed_encryption_line_refuses_on_both_decoders() {
        // A well-formed article whose =yencryption line carries a short
        // salt: with the arm ON this must be BadEncryption everywhere,
        // never a silent skip that hands ciphertext on as plaintext.
        let body = b"=ybegin line=128 size=3 name=x\r\n\
                     =yencryption cipher=XChaCha20-Poly1305 salt=00 tag=00\r\n\
                     +++\r\n\
                     =yend size=3\r\n";
        let mut out = Vec::new();
        let simd = crate::yenc_simd::decode_into_integrity_opts(body, &mut out, true, true);
        let scalar = crate::yenc::decode_checked_opts(body, true);
        assert!(matches!(simd, Err(crate::yenc::YencError::BadEncryption)));
        assert!(matches!(scalar, Err(crate::yenc::YencError::BadEncryption)));
    }

    /// Control-half derivation pin, the FF1 sibling of the body pin
    /// above and for the same reason: this module is both halves of the
    /// wire format, so a convention drift that moves both sides at once
    /// still round-trips, and only a pinned vector catches it. Values
    /// produced by THIS implementation on 31 Aug 2026 under the
    /// declared conventions (physical lineIndex, ascending alphabet
    /// bijection, u32 BE indices), core validated against NIST
    /// FF1-AES256 samples 7-9 in `ff1::tests` - and verified BYTE-EXACT
    /// against the reference implementation the same day
    /// (go-yenc-header-encryption's `DeriveTweak` and `EncryptLine` on
    /// these inputs print exactly these two values).
    #[test]
    fn the_control_derivation_chain_is_pinned_against_silent_drift() {
        let master = derive_key("test123", b"0123456789abcdef");
        let cc = ControlCrypt::new(&master);
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!(
            hex(&cc.tweak(1, 1)),
            "796dd4592cfb5fda",
            "tweak(seg=1, line=1) moved"
        );
        let line = b"=ybegin line=9 size=18 name=file.bin";
        let ct = cc.encrypt_line(1, 1, line).unwrap();
        assert_eq!(
            hex(&ct),
            "9509ddc5ff69dc4ce7e7b0ad3b2b8cfefd61a623163844abe81d34e976694709ff5118fe",
            "line ciphertext moved"
        );
        assert_eq!(cc.decrypt_line(1, 1, &ct).unwrap(), line);
    }

    #[test]
    fn the_control_alphabet_bijection_is_total_and_inverse() {
        let mut seen = [false; 253];
        for b in 0u16..=255 {
            let b = b as u8;
            match alpha_digit(b) {
                None => assert!(
                    b == 0 || b == b'\r' || b == b'\n',
                    "byte {b:#04x} wrongly out"
                ),
                Some(d) => {
                    assert!(u32::from(d) < CONTROL_RADIX, "digit {d} out of radix");
                    assert!(!seen[d as usize], "digit {d} hit twice");
                    seen[d as usize] = true;
                    assert_eq!(alpha_byte(d), b, "inverse broken at byte {b:#04x}");
                }
            }
        }
        assert!(
            seen.iter().all(|&s| s),
            "bijection must cover all 253 numerals"
        );
    }

    /// The draft's own worked example shape (4 lines, CRLF), pinning
    /// the declared lineIndex convention from both directions: the
    /// footer decrypts at its PHYSICAL index (4) and refuses at the
    /// index the draft's buggy step text would derive (2). If this test
    /// ever breaks by someone "fixing" the convention, the wire format
    /// changes and every existing post stops decrypting - that is what
    /// the pin is for.
    #[test]
    fn a_control_block_round_trips_and_the_footer_index_is_physical() {
        let master = derive_key("test123", b"0123456789abcdef");
        let cc = ControlCrypt::new(&master);
        let salt = *b"ABCDEFGHIJKLMNOP";
        let block = b"=ybegin line=9 size=18 name=file.bin\r\n\
                      abcDEF123\r\n\
                      ghiJKL456\r\n\
                      =yend size=18\r\n";
        let enc = control_encrypt_block(&cc, &salt, 7, block).expect("encrypts");
        // Length: +16 for the salt, every other line identical length.
        assert_eq!(enc.len(), block.len() + 16);
        let enc_lines = physical_lines(&enc);
        assert_eq!(enc_lines.len(), 4);
        // Data lines ride through byte-identical.
        assert_eq!(&enc[enc_lines[1].0..enc_lines[1].2], b"abcDEF123\r\n");
        assert_eq!(&enc[enc_lines[2].0..enc_lines[2].2], b"ghiJKL456\r\n");
        // No visible yEnc structure remains.
        assert!(!enc.windows(7).any(|w| w == b"=ybegin"));
        // Round trip.
        let dec = control_decrypt_block(&cc, 7, &enc).expect("decrypts");
        assert_eq!(dec, block);
        // The footer ciphertext decrypts ONLY at lineIndex 4: the
        // reading where only `=y` lines increment (footer index 2)
        // yields garbage, so two implementations split by the draft's
        // contradiction do NOT interoperate - measured, not argued.
        let (fs, fce, _) = enc_lines[3];
        let footer_ct = &enc[fs..fce];
        let at4 = cc.decrypt_line(7, 4, footer_ct).unwrap();
        assert!(at4.starts_with(b"=yend"));
        let at2 = cc.decrypt_line(7, 2, footer_ct).unwrap();
        assert!(
            !at2.starts_with(b"=y"),
            "buggy-reading index must not decrypt"
        );
        // Wrong segment refuses the whole block (line 1 trial fails).
        assert!(control_decrypt_block(&cc, 8, &enc).is_none());
        // A different password's context refuses.
        let other = ControlCrypt::new(&derive_key("test124", b"0123456789abcdef"));
        assert!(control_decrypt_block(&other, 7, &enc).is_none());
        // An unencrypted block is never touched (detection gate).
        assert!(control_block_salt(block).is_none());
    }

    /// A control line is LENGTH-bounded, both halves. FF1's radix-253
    /// digit conversions are quadratic in the line length and nothing
    /// between the socket and the decoder caps a single line, so without
    /// this bound one article whose first line is megabytes of
    /// in-alphabet bytes buys tens of seconds of decode-thread CPU on
    /// the line-1 trial decrypt, before the `=y` commit check that would
    /// have rejected it. The pin is on the SHAPE (refuse vs encipher),
    /// never on a wall clock, which would be contention-sensitive.
    #[test]
    fn an_over_long_control_line_is_refused_rather_than_enciphered() {
        let master = derive_key("test123", b"0123456789abcdef");
        let cc = ControlCrypt::new(&master);

        // At the cap: still a control line, still round-trips.
        let mut at_cap = b"=ybegin line=128 size=1 name=".to_vec();
        at_cap.resize(MAX_CONTROL_LINE, b'x');
        let ct = cc
            .encrypt_line(7, 1, &at_cap)
            .expect("a line at the cap still enciphers");
        assert_eq!(ct.len(), at_cap.len());
        assert_eq!(cc.decrypt_line(7, 1, &ct).expect("round trips"), at_cap);

        // One byte over: both halves refuse before any FF1 work.
        let mut over = at_cap.clone();
        over.push(b'x');
        assert!(
            cc.encrypt_line(7, 1, &over).is_none(),
            "the encoder half must refuse a line past the cap"
        );
        assert!(
            cc.decrypt_line(7, 1, &over).is_none(),
            "the decoder half must refuse a line past the cap"
        );

        // The encoder refuses the whole block rather than emitting one
        // no bounded decoder could ever read back.
        let mut long_block = over.clone();
        long_block.extend_from_slice(b"\r\n=yend size=1\r\n");
        assert!(
            control_encrypt_block(&cc, b"ABCDEFGHIJKLMNOP", 7, &long_block).is_none(),
            "an over-long control line must not be encoded"
        );

        // Block level: the salt gate still accepts a hostile first line
        // (it reads 16 bytes and an alphabet check), and the trial
        // decrypt then refuses WITHOUT running FF1 over the rest, so the
        // article falls through to the ordinary yEnc decoder unchanged -
        // exactly where an unencrypted article already lands.
        let mut hostile = b"ABCDEFGHIJKLMNOP".to_vec();
        hostile.extend_from_slice(&vec![b'x'; MAX_CONTROL_LINE + 1]);
        hostile.extend_from_slice(b"\r\n=yend size=1\r\n");
        assert_eq!(control_block_salt(&hostile), Some(*b"ABCDEFGHIJKLMNOP"));
        assert!(control_decrypt_block(&cc, 7, &hostile).is_none());
    }

    /// Combined mode, declared ordering: body encryption inside,
    /// control lines outside. A combined article decrypts control-first
    /// back to a normal `=yencryption` article, and the multipart
    /// header run (`=ybegin` + `=yencryption`) restores line by line.
    #[test]
    fn combined_body_and_control_encryption_round_trips() {
        let salt = *b"0123456789abcdef";
        let key = derive_key("pw", &salt);
        let cc = ControlCrypt::new(&key);
        let plain: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
        let mut articles = std::collections::HashMap::new();
        let segs = crate::mock::make_file_articles_encrypted(
            "f.bin",
            &plain,
            1500,
            "t",
            &key,
            &salt,
            1,
            &mut articles,
        );
        assert_eq!(segs.len(), 2);
        let mut got = vec![0u8; plain.len()];
        for (i, (id, _, _part)) in segs.iter().enumerate() {
            let body = &articles[&format!("<{id}>")];
            let seg = 1 + i as u32;
            let wrapped = control_encrypt_block(&cc, &salt, seg, body).expect("combined encrypt");
            // Control-decrypt restores the body-encrypted article
            // byte-exact, =yencryption line included.
            let restored = control_decrypt_block(&cc, seg, &wrapped).expect("combined decrypt");
            assert_eq!(&restored, body);
            // And the restored article decodes + body-decrypts as usual.
            let mut out = Vec::new();
            let (m, _integ) =
                crate::yenc_simd::decode_into_integrity_opts(&restored, &mut out, true, true)
                    .unwrap();
            let h = m.encryption.expect("captured");
            assert!(decrypt_segment(&key, seg, &h.tag, &mut out));
            let off = m.offset() as usize;
            got[off..off + out.len()].copy_from_slice(&out);
        }
        assert_eq!(got, plain);
    }

    /// The JobCrypt door the decode loop actually calls: message-id
    /// (bracketed, as the pool spells it) -> segmentIndex -> detection
    /// -> whole-block decrypt, with the salt cached across articles.
    #[test]
    fn job_crypt_control_decrypts_by_message_id() {
        // The helper mints ids per segment NUMBER, so give file 2 its
        // own namespace - two files legitimately never share an id.
        let mut fb = file("[2/2] b.bin", 3);
        for s in &mut fb.segments {
            s.message_id = format!("b-{}@t", s.number);
        }
        let files = vec![file("[1/2] a.bin", 2), fb];
        let jc = JobCrypt {
            password: "test123".into(),
            slot_base: vec![1, 3],
            seg_by_id: {
                let mut m = HashMap::new();
                let bases = file_seg_bases(&files).unwrap();
                for (fi, f) in files.iter().enumerate() {
                    for s in &f.segments {
                        m.insert(s.message_id.clone(), bases[fi] + s.number - 1);
                    }
                }
                m
            },
            keys: Mutex::new(HashMap::new()),
            controls: Mutex::new(HashMap::new()),
        };
        // File 2 segment 1 has session index 3 (continuous numbering);
        // file 1 segment 1 has index 1.
        assert_eq!(jc.segment_index_for_id("<b-1@t>"), Some(3));
        assert_eq!(jc.segment_index_for_id("<id-1@t>"), Some(1));
        let block = b"=ybegin part=1 total=3 line=128 size=9 name=b.bin\r\n\
                      =ypart begin=1 end=9\r\n\
                      datadata1\r\n\
                      =yend size=9 part=1\r\n";
        let salt = *b"saltSALTsaltSALT";
        let cc = ControlCrypt::new(&jc.key_for(&salt));
        let enc = control_encrypt_block(&cc, &salt, 3, block).expect("encrypts");
        let dec = jc
            .control_decrypt_article("<b-1@t>", &enc)
            .expect("decrypts through the id map");
        assert_eq!(dec, block);
        // An id outside the NZB, or the wrong article's id: refused.
        assert!(jc.control_decrypt_article("<stranger@x>", &enc).is_none());
        assert!(jc.control_decrypt_article("<id-1@t>", &enc).is_none());
    }

    #[test]
    fn subject_numbers_parse_the_drafts_required_shape_only() {
        assert_eq!(subject_file_number("[1/3] x.bin"), Some((1, 3)));
        assert_eq!(subject_file_number("  [12/40] y"), Some((12, 40)));
        assert_eq!(subject_file_number("[0/3] x"), None);
        assert_eq!(subject_file_number("[4/3] x"), None);
        assert_eq!(subject_file_number("no prefix"), None);
        assert_eq!(subject_file_number("[a/b] x"), None);
    }
}
