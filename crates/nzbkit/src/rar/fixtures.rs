use crate::rarcrypt;

/// Encode a RAR5 vint.
fn vint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            break;
        }
        out.push(b | 0x80);
    }
}

/// Header bytes (crc + size vint + header data) for one v5 block.
/// `extra` is appended as the header's extra area (flag 0x01).
fn hdr_v5(btype: u64, mut hflags: u64, body: &[u8], extra: &[u8], data_len: u64) -> Vec<u8> {
    let mut hdr = Vec::new();
    if !extra.is_empty() {
        hflags |= 0x01;
    }
    vint(btype, &mut hdr);
    vint(hflags, &mut hdr);
    if !extra.is_empty() {
        vint(extra.len() as u64, &mut hdr);
    }
    if hflags & 0x02 != 0 {
        vint(data_len, &mut hdr);
    }
    hdr.extend_from_slice(body);
    hdr.extend_from_slice(extra);
    let mut sized = Vec::new();
    vint(hdr.len() as u64, &mut sized);
    // CRC covers the header-size vint + header data (spec).
    let mut crc = crc32fast::Hasher::new();
    crc.update(&sized);
    crc.update(&hdr);
    let mut out = Vec::new();
    out.extend_from_slice(&crc.finalize().to_le_bytes());
    out.extend_from_slice(&sized);
    out.extend_from_slice(&hdr);
    out
}

fn block_v5(btype: u64, hflags: u64, body: &[u8], data: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&hdr_v5(btype, hflags, body, &[], data.len() as u64));
    out.extend_from_slice(data);
}

/// A RAR4 volume whose MAIN HEADER carries MHD_PASSWORD (0x0080),
/// padded with `pad` bytes of junk standing in for encrypted blocks.
/// The "a password is required" shape, for probes that ask exactly
/// that - the junk is not real ciphertext, so a mapper GIVEN a
/// password rejects it; use [`rar4_volume_enc_headers`] for a set that
/// actually decrypts.
pub fn rar4_encrypted_headers(pad: usize) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(super::SIG4);
    // The main header stays PLAINTEXT even under MHD_PASSWORD, so it
    // carries a real CRC like any other plaintext block.
    out.extend_from_slice(&rar4_main_header(true));
    out.extend(std::iter::repeat_n(0xA5, pad));
    out
}

/// One store-mode RAR5 volume holding the given (name, total_size,
/// piece, split_before, split_after) pieces. No volume-number field
/// (like a standalone .rar) - use [`rar5_volume_n`] for numbered sets.
///
/// Carries NO data CRC, same as [`rar5_volume_n`] - read the warning
/// there before using this under a test that damages bytes.
pub fn rar5_volume(pieces: &[(&str, u64, &[u8], bool, bool)]) -> Vec<u8> {
    let with_crc: Vec<_> = pieces
        .iter()
        .map(|&(n, t, p, b, a)| (n, t, p, b, a, None))
        .collect();
    rar5_volume_inner(&with_crc, None, &[])
}

/// Numbered multi-volume member (RAR5 volume_number, 0-based).
///
/// **Emits NO data CRC**: file flag 0x04 is never set and no checksum
/// rides any piece, unlike real archivers, which always stamp one. That
/// is deliberate and fine for the many tests that only exercise
/// parsing, mapping, holds, splitting and the like - nothing in those
/// paths ever looks at a CRC.
///
/// But a test that DAMAGES bytes and then asserts an extraction
/// succeeds must not reach for this blind. With no checksum anywhere
/// the extraction succeeds on the corrupt bytes too, so the "damaged,
/// repaired, extraction verifies" leg greens whether or not the repair
/// did anything, and proves nothing. Either build the set with
/// [`rar5_volume_n_crc`], or compare the extracted payload to the
/// posted bytes byte for byte, or open the leg with an
/// `assert!(!try_unrar(..))` control that shows the damage is real -
/// `assert_the_fixture_is_really_damaged` in
/// `crates/nzbfast/src/rarfix/rrhint_tests.rs` is the worked example.
/// This warning exists because on 22 Aug 2026 the vendored
/// `Rar50VolumeWriter` was found to write no CRC on split STORED
/// members either, so six such legs had been passing over bytes nothing
/// verified (the 2026-08-22 row in `vendor/rars/VENDORING.md`); this
/// fixture has the same hole, on purpose, under a name with dozens of
/// call sites.
///
/// And the absence is LOAD-BEARING in one place, so do not "fix" it
/// tree-wide: e2e's `rar_release` in `crates/nzbfast/tests/e2e.rs`
/// builds on this fixture precisely so its volumes carry neither a
/// recovery record nor a CRC, which is the shape
/// `a_missing_external_par2_still_reaches_the_native_escalation` needs
/// to pin the `nothing_done` guard in `try_rar_rr_repair_hinted`. Both
/// carry doc comments saying so.
pub fn rar5_volume_n(pieces: &[(&str, u64, &[u8], bool, bool)], vol_no: u64) -> Vec<u8> {
    let with_crc: Vec<_> = pieces
        .iter()
        .map(|&(n, t, p, b, a)| (n, t, p, b, a, None))
        .collect();
    rar5_volume_inner(&with_crc, Some(vol_no), &[])
}

/// Like [`rar5_volume_n`], with a stored data CRC32 per piece (file
/// flag 0x04) the way real archivers always write it. Per the RAR5
/// spec the value is the CRC32 of the whole unpacked file on an
/// unsplit entry and on the LAST split piece (the one unrar checks),
/// and of the current volume's packed piece bytes on earlier pieces
/// (store mode packs 1:1).
pub fn rar5_volume_n_crc(
    pieces: &[(&str, u64, &[u8], bool, bool, Option<u32>)],
    vol_no: u64,
) -> Vec<u8> {
    rar5_volume_inner(pieces, Some(vol_no), &[])
}

/// [`rar5_volume_n`] with a SERVICE block (type 3, the shape of a `-rr`
/// recovery record) carrying `service` bytes of data area between the
/// last file block and the end-of-archive block. Real `rar a -rr10p`
/// volumes end exactly this way: file data, then a record a tenth the
/// volume's size, then the 7-byte end block.
///
/// Like its base, this stamps NO data CRC on the file block - the
/// service block is just bytes, not a checksum over the file - so the
/// warning on [`rar5_volume_n`] applies here too: a test that damages
/// these volumes must show the damage is real before trusting a
/// successful extraction.
pub fn rar5_volume_n_service(
    pieces: &[(&str, u64, &[u8], bool, bool)],
    vol_no: u64,
    service: &[u8],
) -> Vec<u8> {
    let with_crc: Vec<_> = pieces
        .iter()
        .map(|&(n, t, p, b, a)| (n, t, p, b, a, None))
        .collect();
    rar5_volume_inner(&with_crc, Some(vol_no), service)
}

fn rar5_volume_inner(
    pieces: &[(&str, u64, &[u8], bool, bool, Option<u32>)],
    vol_no: Option<u64>,
    service: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(super::SIG5);
    // Main archive header (type 1): archive flags vint; volume sets
    // carry 0x01 (volume) and, past the first volume, 0x02 + number.
    let mut main_body = Vec::new();
    match vol_no {
        Some(0) => vint(0x01, &mut main_body),
        Some(n) => {
            vint(0x03, &mut main_body);
            vint(n, &mut main_body);
        }
        None => vint(0x00, &mut main_body),
    }
    block_v5(1, 0, &main_body, &[], &mut out);
    for &(name, total, piece, before, after, crc) in pieces {
        let mut body = Vec::new();
        // File flags: no mtime, not dir; 0x04 when a data CRC rides.
        vint(if crc.is_some() { 0x04 } else { 0 }, &mut body);
        vint(total, &mut body); // unpacked size
        vint(0, &mut body); // attributes
        if let Some(c) = crc {
            body.extend_from_slice(&c.to_le_bytes());
        }
        vint(0, &mut body); // compression info: method 0 = store
        vint(0, &mut body); // host os
        vint(name.len() as u64, &mut body);
        body.extend_from_slice(name.as_bytes());
        let mut hflags = 0x02; // data area present
        if before {
            hflags |= 0x08;
        }
        if after {
            hflags |= 0x10;
        }
        block_v5(2, hflags, &body, piece, &mut out);
    }
    if !service.is_empty() {
        // Service header body: file-style flags, unpacked size,
        // attributes, compression info, host os, name ("RR").
        let mut body = Vec::new();
        vint(0, &mut body);
        vint(service.len() as u64, &mut body);
        vint(0, &mut body);
        vint(0, &mut body);
        vint(0, &mut body);
        vint(2, &mut body);
        body.extend_from_slice(b"RR");
        block_v5(3, 0x02, &body, service, &mut out);
    }
    // End of archive (type 5) with end-flags body (0 = last volume).
    let mut end_body = Vec::new();
    vint(0, &mut end_body);
    block_v5(5, 0, &end_body, &[], &mut out);
    out
}

/// HOSTILE fixture: a single-file store RAR5 volume whose file block
/// DECLARES `declared_data` bytes of data area while only `data` is
/// really there, and which ends immediately after those real bytes (no
/// end-of-archive block - the parser would never reach it anyway).
/// This is the "declared size exceeds what was posted" shape: without
/// the volume-bounds check the cursor jumps past the volume end, the
/// EOF rule calls the volume complete, and a mostly-sparse
/// `unpacked_size`-long file ships as a successful extraction.
pub fn rar5_volume_oversized(
    name: &str,
    unpacked_size: u64,
    data: &[u8],
    declared_data: u64,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(super::SIG5);
    let mut main_body = Vec::new();
    vint(0x00, &mut main_body);
    block_v5(1, 0, &main_body, &[], &mut out);
    let mut body = Vec::new();
    vint(0, &mut body); // file flags: no CRC
    vint(unpacked_size, &mut body);
    vint(0, &mut body); // attributes
    vint(0, &mut body); // compression info: store
    vint(0, &mut body); // host os
    vint(name.len() as u64, &mut body);
    body.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&hdr_v5(2, 0x02, &body, &[], declared_data));
    out.extend_from_slice(data);
    out
}

/// Stamp a RAR4 block's header CRC16 over `h[2..]` - what a real
/// writer does, and since the M5 fix what the plaintext parser
/// insists on. Every RAR4 fixture here goes through it, so a fixture
/// can no longer accidentally stand in for a corrupt header.
pub fn stamp_v4_head_crc(h: &mut [u8]) {
    let hc = (crc32fast::hash(&h[2..]) & 0xffff) as u16;
    h[..2].copy_from_slice(&hc.to_le_bytes());
}

/// Restamp the RAR4 block header starting at `off` after a test has
/// poked one of its fields. Since the M5 fix the plaintext parser
/// checks the header CRC16, so a poke left unrestamped would test
/// the CRC gate instead of the field the test is about.
pub fn restamp_v4_block(vol: &mut [u8], off: usize) {
    let hsize = u16::from_le_bytes(vol[off + 5..off + 7].try_into().unwrap()) as usize;
    stamp_v4_head_crc(&mut vol[off..off + hsize]);
}

/// Where the first block after a RAR4 volume's signature + main
/// header starts: 7-byte marker, 13-byte main header.
pub const V4_FIRST_BLOCK: usize = 20;

/// One store-mode RAR4 volume.
pub fn rar4_volume(pieces: &[(&str, u64, &[u8], bool, bool)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(super::SIG4);
    out.extend_from_slice(&rar4_main_header(false));
    for &(name, total, piece, before, after) in pieces {
        let mut flags: u16 = 0x8000; // add size present
        if before {
            flags |= 0x0001;
        }
        if after {
            flags |= 0x0002;
        }
        let name_b = name.as_bytes();
        let hsize = (7 + 4 + 4 + 1 + 4 + 4 + 1 + 1 + 2 + 4 + name_b.len()) as u16;
        let mut h = Vec::with_capacity(hsize as usize);
        h.extend_from_slice(&0u16.to_le_bytes()); // head crc, stamped below
        h.push(0x74);
        h.extend_from_slice(&flags.to_le_bytes());
        h.extend_from_slice(&hsize.to_le_bytes());
        h.extend_from_slice(&(piece.len() as u32).to_le_bytes()); // add size
        h.extend_from_slice(&(total as u32).to_le_bytes()); // unp size
        h.push(0); // host
        // Whole-file CRC32 (RAR4 header field). Only a complete, single
        // piece can carry it here - a split piece's real whole-file CRC
        // spans data this call doesn't hold, so leave those 0. The parser
        // reads a 0 field as "not computed" (see `file_crc`), so a split
        // fixture exercises mapping without tripping the output-CRC gate.
        // Real writers put the whole-file CRC on the FINAL fragment
        // (vendor/rars/src/rar15_40/write.rs); a multi-volume test of the
        // gate itself therefore needs a fixture that can set it.
        let crc = if !before && !after {
            crc32fast::hash(piece)
        } else {
            0
        };
        h.extend_from_slice(&crc.to_le_bytes()); // crc
        h.extend_from_slice(&0u32.to_le_bytes()); // time
        h.push(29); // unp_ver
        h.push(0x30); // method: store
        h.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
        h.extend_from_slice(&0u32.to_le_bytes()); // attr
        h.extend_from_slice(name_b);
        stamp_v4_head_crc(&mut h);
        out.extend_from_slice(&h);
        out.extend_from_slice(piece);
    }
    out.extend_from_slice(&rar4_end_block());
    out
}

// -- encrypted RAR4 fixtures (mirror what the vendored rars writer
//    emits for `-m0 -p`/`-hp`, which testdata/rar4/ pins against
//    `unrar t`) --

/// One inner file encrypted the way RAR4 does it: ONE AES-128-CBC
/// stream over the whole file from the key schedule's own IV,
/// zero-padded to 16 at the very end. Volumes carve arbitrary byte
/// ranges out of `cipher` and repeat the same salt in every header.
pub struct EncFile4 {
    pub(crate) plain_len: u64,
    pub cipher: Vec<u8>,
    pub(crate) salt: [u8; 8],
    /// CRC32 of the PLAINTEXT - what a RAR4 header stores, and the
    /// only thing that can adjudicate the password at finish.
    pub(crate) crc: u32,
}

/// Encrypt `plain` as one RAR4 file stream.
pub fn encrypt_file_v4(password: &str, plain: &[u8], seed: u8) -> EncFile4 {
    let salt: [u8; 8] = seed16(seed, 7)[..8].try_into().unwrap();
    let keys = rarcrypt::derive_keys_v4(password, Some(salt));
    let mut cipher = plain.to_vec();
    cipher.resize(rarcrypt::align16(plain.len() as u64) as usize, 0);
    rarcrypt::CbcEncStream::new(&rarcrypt::AesKey::Aes128(keys.key), &keys.iv).encrypt(&mut cipher);
    EncFile4 {
        plain_len: plain.len() as u64,
        cipher,
        salt,
        crc: crc32fast::hash(plain),
    }
}

type EncPiece4<'a> = (&'a str, &'a EncFile4, std::ops::Range<usize>, bool, bool);

/// A RAR4 file-header block for one encrypted piece, WITHOUT the data
/// area. `head_crc` is filled in for real: the `-hp` reader checks it,
/// and it is what tells a wrong password from a real header.
fn rar4_enc_file_header(piece: &EncPiece4<'_>) -> Vec<u8> {
    let (name, f, range, before, after) = piece;
    let mut flags: u16 = 0x8000 | 0x0004 | super::FHD_SALT; // add size, encrypted, salt
    if *before {
        flags |= 0x0001;
    }
    if *after {
        flags |= 0x0002;
    }
    let name_b = name.as_bytes();
    let hsize = (32 + name_b.len() + 8) as u16;
    let mut h = Vec::with_capacity(hsize as usize);
    h.extend_from_slice(&0u16.to_le_bytes()); // head crc, patched below
    h.push(0x74);
    h.extend_from_slice(&flags.to_le_bytes());
    h.extend_from_slice(&hsize.to_le_bytes());
    h.extend_from_slice(&(range.len() as u32).to_le_bytes()); // packed
    h.extend_from_slice(&(f.plain_len as u32).to_le_bytes()); // unpacked
    h.push(3); // host os
    // Real writers stamp the WHOLE-FILE plaintext CRC on the final
    // fragment only; earlier fragments describe their own volume's
    // packed bytes (vendor/rars/src/rar15_40/write.rs).
    let crc = if *after {
        crc32fast::hash(&f.cipher[range.clone()])
    } else {
        f.crc
    };
    h.extend_from_slice(&crc.to_le_bytes());
    h.extend_from_slice(&0u32.to_le_bytes()); // time
    h.push(29); // unp_ver: RAR 2.9 = the AES-128 schedule
    h.push(0x30); // method: store
    h.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
    h.extend_from_slice(&0u32.to_le_bytes()); // attr
    h.extend_from_slice(name_b);
    h.extend_from_slice(&f.salt);
    let hc = (crc32fast::hash(&h[2..]) & 0xffff) as u16;
    h[..2].copy_from_slice(&hc.to_le_bytes());
    h
}

/// `vol` with a WinRAR-shaped ENDARC block appended: flags 0x4001
/// (next volume follows, skip if unknown), as every non-final volume of
/// a real RAR3 set carries. The rars v4 writer emits none, and without
/// one a volume whose data runs to its end needs no tail read at all -
/// which hides exactly the wait TODO 220 is about.
pub fn with_rar4_end_block(mut vol: Vec<u8>, next_volume: bool) -> Vec<u8> {
    let mut h = vec![0u8, 0];
    h.push(0x7b);
    h.extend_from_slice(&(if next_volume { 0x4001u16 } else { 0x4000 }).to_le_bytes());
    h.extend_from_slice(&7u16.to_le_bytes());
    let hc = (crc32fast::hash(&h[2..]) & 0xffff) as u16;
    h[..2].copy_from_slice(&hc.to_le_bytes());
    vol.extend_from_slice(&h);
    vol
}

fn rar4_end_block() -> Vec<u8> {
    let mut h = vec![0u8, 0];
    h.push(0x7b);
    h.extend_from_slice(&0u16.to_le_bytes());
    h.extend_from_slice(&7u16.to_le_bytes());
    let hc = (crc32fast::hash(&h[2..]) & 0xffff) as u16;
    h[..2].copy_from_slice(&hc.to_le_bytes());
    h
}

fn rar4_main_header(password_flag: bool) -> Vec<u8> {
    let mut h = vec![0u8, 0];
    h.push(0x73);
    h.extend_from_slice(&(if password_flag { 0x0080u16 } else { 0 }).to_le_bytes());
    h.extend_from_slice(&13u16.to_le_bytes());
    h.extend_from_slice(&[0u8; 6]); // reserved
    let hc = (crc32fast::hash(&h[2..]) & 0xffff) as u16;
    h[..2].copy_from_slice(&hc.to_le_bytes());
    h
}

/// Encrypted-DATA RAR4 volume (`rar -m0 -p…` shape): plaintext
/// headers, AES-128-CBC file data.
pub fn rar4_volume_enc(pieces: &[EncPiece4<'_>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(super::SIG4);
    out.extend_from_slice(&rar4_main_header(false));
    for p in pieces {
        out.extend_from_slice(&rar4_enc_file_header(p));
        out.extend_from_slice(&p.1.cipher[p.2.clone()]);
    }
    out.extend_from_slice(&rar4_end_block());
    out
}

/// Encrypted-HEADER RAR4 volume (`rar -m0 -hp…` shape): the marker and
/// main header stay plaintext (that is how the MHD_PASSWORD flag is
/// readable at all), and every block after them is an 8-byte salt
/// followed by its own AES-128-CBC stream padded to 16.
pub fn rar4_volume_enc_headers(pieces: &[EncPiece4<'_>], password: &str, seed: u8) -> Vec<u8> {
    let salt: [u8; 8] = seed16(seed, 8)[..8].try_into().unwrap();
    let keys = rarcrypt::derive_keys_v4(password, Some(salt));
    let aes = rarcrypt::AesKey::Aes128(keys.key);
    let mut out = Vec::new();
    out.extend_from_slice(super::SIG4);
    out.extend_from_slice(&rar4_main_header(true));
    let wrap = |hdr: Vec<u8>, out: &mut Vec<u8>| {
        let mut cipher = hdr;
        cipher.resize(rarcrypt::align16(cipher.len() as u64) as usize, 0);
        rarcrypt::CbcEncStream::new(&aes, &keys.iv).encrypt(&mut cipher);
        out.extend_from_slice(&salt);
        out.extend_from_slice(&cipher);
    };
    for p in pieces {
        wrap(rar4_enc_file_header(p), &mut out);
        out.extend_from_slice(&p.1.cipher[p.2.clone()]);
    }
    wrap(rar4_end_block(), &mut out);
    out
}

// -- encrypted RAR5 fixtures (mirror what real `rar -m0 -p/-hp`
//    emits; the format facts are pinned by the testdata KATs) --

/// One inner file encrypted the way RAR5 does it: ONE AES-256-CBC
/// stream over the whole file, zero-padded to 16 at the very end.
/// Volumes carve arbitrary byte ranges out of `cipher` and repeat the
/// same (salt, iv, check) in every piece's header.
pub struct EncFile {
    pub(crate) plain_len: u64,
    pub cipher: Vec<u8>,
    pub(crate) lg2_count: u8,
    pub(crate) salt: [u8; 16],
    pub(crate) iv: [u8; 16],
    pub(crate) check: [u8; 12],
    /// Plaintext CRC32 written into the file header (flag 0x04) when
    /// `with_crc` is set - exercises the post-decrypt verify path.
    pub(crate) crc: u32,
    pub(crate) with_crc: bool,
    /// Set the crypt record's tweaked-checksum flag (0x02): the stored
    /// CRC is then treated as untrustworthy for a plain comparison.
    pub(crate) tweaked: bool,
    /// Omit the password-check value (crypt flag 0x01 cleared) - the
    /// rare WinRAR "don't store password check" case.
    pub(crate) no_check: bool,
    /// TEST-ONLY: write the whole-file check records (the CRC32 file
    /// flag, FHEXTRA_HASH) on NON-tail pieces as well. No real writer
    /// does this - a whole-file check describes the whole file - which
    /// is exactly what makes it the fixture for a head and a tail that
    /// DISAGREE about a check field. The route decision has to answer
    /// the same for both or one output gets half of each route (TODO
    /// 158 item 2).
    pub(crate) checks_on_head: bool,
    /// Write an FHEXTRA_HASH record (type 0x02) carrying a BLAKE2sp
    /// digest - `rar a -htb`. Set WITHOUT `with_crc` this is the
    /// hash-only shape: a plaintext check nzbkit cannot compute, so no
    /// in-stream path may publish the output. The digest bytes are
    /// arbitrary here: nothing in nzbkit hashes plaintext, so what the
    /// tests exercise is the ROUTING, not a comparison.
    pub(crate) with_hash: bool,
    /// The password these parameters were derived from - needed to
    /// re-derive `hash_key` when `tweaked` folds the stored CRC.
    pub password: String,
}

/// Deterministic 16 bytes from a seed (fixtures must be reproducible).
fn seed16(seed: u8, tweak: u8) -> [u8; 16] {
    let mut b = [0u8; 16];
    for (i, x) in b.iter_mut().enumerate() {
        *x = (i as u8)
            .wrapping_mul(37)
            .wrapping_add(seed)
            .wrapping_mul(59)
            .wrapping_add(tweak);
    }
    b
}

/// Encrypt `plain` as one RAR5 file stream. `lg2_count` 12 keeps test
/// KDFs fast; real archives use 15.
pub fn encrypt_file(password: &str, plain: &[u8], seed: u8) -> EncFile {
    let lg2_count = 12u8;
    let salt = seed16(seed, 1);
    let iv = seed16(seed, 2);
    let keys = rarcrypt::derive_keys(password, &salt, lg2_count).unwrap();
    let mut cipher = plain.to_vec();
    cipher.resize(rarcrypt::align16(plain.len() as u64) as usize, 0);
    rarcrypt::CbcEncStream::new(&keys.aes(), &iv).encrypt(&mut cipher);
    EncFile {
        plain_len: plain.len() as u64,
        cipher,
        lg2_count,
        salt,
        iv,
        check: rarcrypt::make_check(&keys),
        crc: crc32fast::hash(plain),
        with_crc: false,
        tweaked: false,
        no_check: false,
        checks_on_head: false,
        with_hash: false,
        password: password.to_string(),
    }
}

/// The file-encryption extra record (type 0x01) for `f`, plus the
/// file-hash record (type 0x02) when `f.with_hash` and this is the
/// TAIL piece.
///
/// Tail-only (unless `f.checks_on_head`) for the same reason the
/// CRC32 is: a whole-file check describes the whole file, and real
/// RAR5 writes it on the unsplit entry or the last fragment. A
/// fixture that stamped it on every piece would be testing a shape no
/// archive has. `checks_on_head` asks for exactly that shape on
/// purpose: it is how the TODO 158 item 2 tests build a head and a
/// tail that disagree about a check field, which the route decision
/// has to answer identically for or one output gets half of each
/// route.
fn crypt_extra(f: &EncFile, tail: bool) -> Vec<u8> {
    let mut body = Vec::new();
    vint(0x01, &mut body); // record type: encryption
    vint(0, &mut body); // version
    let cflags = if f.no_check { 0 } else { 0x01 } | if f.tweaked { 0x02 } else { 0 };
    vint(cflags, &mut body); // flags: [check value present] [+ tweaked]
    body.push(f.lg2_count);
    body.extend_from_slice(&f.salt);
    body.extend_from_slice(&f.iv);
    if !f.no_check {
        body.extend_from_slice(&f.check);
    }
    let mut out = Vec::new();
    vint(body.len() as u64, &mut out);
    out.extend_from_slice(&body);
    if f.with_hash && tail {
        let mut h = Vec::new();
        vint(0x02, &mut h); // record type: file hash
        vint(0, &mut h); // hash type: BLAKE2sp
        h.extend_from_slice(&[0xAB; 32]);
        vint(h.len() as u64, &mut out);
        out.extend_from_slice(&h);
    }
    out
}

/// (header bytes, data bytes) for every block of an encrypted-data
/// volume. `pieces` = (name, file, cipher range, split_before,
/// split_after).
type EncPiece<'a> = (&'a str, &'a EncFile, std::ops::Range<usize>, bool, bool);

fn enc_volume_blocks(pieces: &[EncPiece<'_>], vol_no: Option<u64>) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut blocks = Vec::new();
    let mut main_body = Vec::new();
    match vol_no {
        Some(0) => vint(0x01, &mut main_body),
        Some(n) => {
            vint(0x03, &mut main_body);
            vint(n, &mut main_body);
        }
        None => vint(0x00, &mut main_body),
    }
    blocks.push((hdr_v5(1, 0, &main_body, &[], 0), Vec::new()));
    for (name, f, range, before, after) in pieces {
        let mut body = Vec::new();
        // Real RAR5 writes the WHOLE-FILE checksum on the unsplit
        // entry and on the LAST split piece only; earlier pieces
        // describe their own volume's bytes. Fixtures that stamped
        // the whole-file value on every piece let a head-only
        // lookup pass a test the tail lookup is what actually makes
        // work in the field, so only the tail carries it here -
        // unless a disagreement fixture asked for the opposite
        // (`checks_on_head`).
        let tail = !*after || f.checks_on_head;
        vint(if f.with_crc && tail { 0x04 } else { 0 }, &mut body); // file flags
        vint(f.plain_len, &mut body); // unpacked size
        vint(0, &mut body); // attributes
        if f.with_crc && tail {
            // A tweaked-checksum archive stores the KEYED FOLD of the
            // plaintext CRC32, not the CRC itself (WinRAR's
            // ConvertHashToMAC) - a fixture that stored the bare CRC
            // under a set tweaked flag would be testing a shape no
            // real archive has.
            let stored = if f.tweaked {
                let keys = rarcrypt::derive_keys(&f.password, &f.salt, f.lg2_count)
                    .expect("fixture KDF count is sane");
                rarcrypt::mac_crc32(&keys, f.crc)
            } else {
                f.crc
            };
            body.extend_from_slice(&stored.to_le_bytes());
        }
        vint(0, &mut body); // compression info: store
        vint(0, &mut body); // host os
        vint(name.len() as u64, &mut body);
        body.extend_from_slice(name.as_bytes());
        let mut hflags = 0x02;
        if *before {
            hflags |= 0x08;
        }
        if *after {
            hflags |= 0x10;
        }
        let piece = &f.cipher[range.clone()];
        blocks.push((
            hdr_v5(2, hflags, &body, &crypt_extra(f, tail), piece.len() as u64),
            piece.to_vec(),
        ));
    }
    let mut end_body = Vec::new();
    vint(0, &mut end_body);
    blocks.push((hdr_v5(5, 0, &end_body, &[], 0), Vec::new()));
    blocks
}

/// Encrypted-DATA volume (`rar -m0 -p…` shape): plaintext headers,
/// AES-256-CBC file data.
pub fn rar5_volume_enc(pieces: &[EncPiece<'_>], vol_no: Option<u64>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(super::SIG5);
    for (hdr, data) in enc_volume_blocks(pieces, vol_no) {
        out.extend_from_slice(&hdr);
        out.extend_from_slice(&data);
    }
    out
}

/// Encrypted-HEADER volume (`rar -m0 -hp…` shape): a plaintext type-4
/// crypt block, then every header wrapped as 16-byte IV + ciphertext
/// (padded to 16); file data encrypted as in [`rar5_volume_enc`].
pub fn rar5_volume_enc_headers(
    pieces: &[EncPiece<'_>],
    vol_no: Option<u64>,
    password: &str,
    seed: u8,
) -> Vec<u8> {
    let lg2_count = 12u8;
    let salt = seed16(seed, 3);
    let keys = rarcrypt::derive_keys(password, &salt, lg2_count).unwrap();
    let mut out = Vec::new();
    out.extend_from_slice(super::SIG5);
    let mut crypt_body = Vec::new();
    vint(0, &mut crypt_body); // version: AES-256
    vint(0x01, &mut crypt_body); // flags: check present
    crypt_body.push(lg2_count);
    crypt_body.extend_from_slice(&salt);
    crypt_body.extend_from_slice(&rarcrypt::make_check(&keys));
    out.extend_from_slice(&hdr_v5(4, 0, &crypt_body, &[], 0));
    for (bi, (hdr, data)) in enc_volume_blocks(pieces, vol_no).into_iter().enumerate() {
        let iv = seed16(seed.wrapping_add(bi as u8), 4);
        let mut cipher = hdr;
        cipher.resize(rarcrypt::align16(cipher.len() as u64) as usize, 0);
        rarcrypt::CbcEncStream::new(&keys.aes(), &iv).encrypt(&mut cipher);
        out.extend_from_slice(&iv);
        out.extend_from_slice(&cipher);
        out.extend_from_slice(&data);
    }
    out
}
