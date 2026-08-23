//! RAR4 mapping against bytes a REAL archiver wrote.
//!
//! `tests.rs` already drives `testdata/rar4/`, but those archives came
//! out of the vendored rars fork's own RAR4 writer, so the reader only
//! ever meets field combinations that writer knows how to emit -
//! `unrar t` accepting them proves the writer valid, not the reader
//! complete. `fixtures.rs` has the mirror-image blind spot: a
//! hand-built volume encodes our own reading of the format, so a
//! misunderstanding shared by fixture and parser passes every test.
//!
//! These fixtures come from RARLAB `rar` 6.24 instead, on two hosts,
//! and every fact asserted below is one the archiver chose. See
//! `testdata/rar4-archiver/README.md` for the provenance table and the
//! switches each shape was written with. A child module (the
//! v4_header_tests.rs pattern) so rar.rs stays inside its size-gate
//! entry; `super::*` reaches the private parser.

use super::*;

const PW: &str = "testpw123";

const MAC_STORE: &[u8] = include_bytes!("../../testdata/rar4-archiver/mac-store.rar");
const MAC_VOL0: &[u8] = include_bytes!("../../testdata/rar4-archiver/mac-oldvol.rar");
const MAC_VOL1: &[u8] = include_bytes!("../../testdata/rar4-archiver/mac-oldvol.r00");
const MAC_VOL2: &[u8] = include_bytes!("../../testdata/rar4-archiver/mac-oldvol.r01");
const MAC_VOL3: &[u8] = include_bytes!("../../testdata/rar4-archiver/mac-oldvol.r02");
const MAC_RR_COMMENT: &[u8] = include_bytes!("../../testdata/rar4-archiver/mac-rr-comment.rar");
const MAC_UNICODE: &[u8] = include_bytes!("../../testdata/rar4-archiver/mac-unicode.rar");
const MAC_LARGE_TAIL: &[u8] = include_bytes!("../../testdata/rar4-archiver/mac-large-tail.r03");
const WIN_STORE: &[u8] = include_bytes!("../../testdata/rar4-archiver/win-store.rar");
const WIN_FULLWIDTH: &[u8] = include_bytes!("../../testdata/rar4-archiver/win-fullwidth.rar");
const WIN_FULLWIDTH_LONG: &[u8] =
    include_bytes!("../../testdata/rar4-archiver/win-fullwidth-long.rar");
const WIN_VOL0: &[u8] = include_bytes!("../../testdata/rar4-archiver/win-oldvol.rar");
const WIN_VOL1: &[u8] = include_bytes!("../../testdata/rar4-archiver/win-oldvol.r00");
const WIN_VOL2: &[u8] = include_bytes!("../../testdata/rar4-archiver/win-oldvol.r01");
const WIN_VOL3: &[u8] = include_bytes!("../../testdata/rar4-archiver/win-oldvol.r02");
const WIN_ENCHDR: &[u8] = include_bytes!("../../testdata/rar4-archiver/win-enchdr.rar");
const WIN_ENCVOL0: &[u8] = include_bytes!("../../testdata/rar4-archiver/win-encvol.rar");
const WIN_ENCVOL1: &[u8] = include_bytes!("../../testdata/rar4-archiver/win-encvol.r00");
const WIN_ENCVOL2: &[u8] = include_bytes!("../../testdata/rar4-archiver/win-encvol.r01");
const WIN_ENCVOL3: &[u8] = include_bytes!("../../testdata/rar4-archiver/win-encvol.r02");

fn map(pw: Option<&str>, vol: &[u8]) -> VolumeMapper {
    let mut m = VolumeMapper::with_password(vol.len() as u64, pw.map(std::sync::Arc::from));
    m.feed(0, vol);
    m
}

/// The one entry of a single-member volume, with the volume required to
/// have mapped cleanly all the way to its end block.
fn only_entry(m: &VolumeMapper) -> &FileEntry {
    assert_eq!(m.blocker, None, "volume must map");
    assert!(m.complete, "volume must read complete");
    assert_eq!(m.entries.len(), 1);
    &m.entries[0]
}

/// The bytes the mapper says are this entry's data area, taken out of
/// the volume at the offset and length it reported.
///
/// This is the assertion that actually costs something: a wrong
/// `data_off` or `data_len` survives an equality check against a number
/// this same parser produced, and does NOT survive being used to cut the
/// payload back out and checksum it against what the archiver stamped.
fn data_area<'a>(vol: &'a [u8], e: &FileEntry) -> &'a [u8] {
    let off = e.data_off as usize;
    let end = off + e.data_len as usize;
    assert!(end <= vol.len(), "data area {off}..{end} outside volume");
    &vol[off..end]
}

#[test]
fn mac_single_volume_store_maps() {
    let m = map(None, MAC_STORE);
    let e = only_entry(&m);
    assert_eq!(e.name, "inner.bin");
    assert_eq!(e.method, Method::Store);
    assert!(!e.encrypted && !e.is_dir);
    assert!(!e.split_before && !e.split_after);
    assert_eq!(e.unpacked_size, 1000);
    assert_eq!(e.data_len, 1000, "a plaintext store area is not padded");
    // The archiver's own CRC32, over the bytes the mapper points at.
    assert_eq!(e.file_crc, Some(crc32fast::hash(data_area(MAC_STORE, e))));
}

/// A real archiver closes an archive with an end-of-archive block; the
/// vendored writer emits none, so `testdata/rar4/` can only ever reach
/// `complete` down the "EOF with no end block" arm. This volume reaches
/// it down the other one, and the two are different code paths.
#[test]
fn mac_store_ends_on_a_real_end_block() {
    let e_end = {
        let m = map(None, MAC_STORE);
        let e = only_entry(&m);
        e.data_off + e.data_len
    };
    assert!(
        e_end < MAC_STORE.len() as u64,
        "the archiver wrote trailing bytes after the data area"
    );
    assert_eq!(MAC_STORE[e_end as usize + 2], 0x7b, "end-of-archive block");
}

/// A recovery record and an archive comment are both sub-blocks the
/// mapper has to walk past, and both sit BEFORE the member, so getting
/// either length wrong moves the data area.
#[test]
fn mac_recovery_record_and_comment_are_skipped() {
    let m = map(None, MAC_RR_COMMENT);
    let e = only_entry(&m);
    assert_eq!(e.name, "inner.bin");
    assert_eq!(e.unpacked_size, 1000);
    let plain = map(None, MAC_STORE);
    assert!(
        e.data_off > plain.entries[0].data_off,
        "the sub-blocks push the member later in the volume"
    );
    assert_eq!(
        e.file_crc,
        Some(crc32fast::hash(data_area(MAC_RR_COMMENT, e))),
        "same payload, found at the shifted offset"
    );
}

/// `FHD_UNICODE` from a Unix archiver: encoder modes 0, 1, 2 and a
/// mode-3 run with no correction byte all appear in this one name.
///
/// `U+F4E6` is not a decode fault. The name on disk ends in `U+1F4E6`,
/// and rar's Unix build truncated it to 16 bits when it wrote the field;
/// unrar reads the same lossy name back, so this value IS the reference
/// decoder's answer. Asserting anything else would be asserting we
/// disagree with unrar about a name.
#[test]
fn mac_unicode_name_matches_the_reference_decoder() {
    let m = map(None, MAC_UNICODE);
    let e = only_entry(&m);
    assert_eq!(e.name, "na\u{ef}ve-\u{65e5}\u{672c}\u{8a9e}-\u{f4e6}.bin");
    assert_eq!(e.unpacked_size, 1000);
}

/// `LHD_LARGE`: the header carries `high_pack` and `high_unp` between
/// the attribute field and the name, so every field after them shifts by
/// eight bytes. This is the FINAL volume of a >4 GiB split store, which
/// is why it is 477 bytes and still declares a member of 4 GiB + 7.
#[test]
fn mac_large_header_reads_the_64_bit_halves() {
    let m = map(None, MAC_LARGE_TAIL);
    let e = only_entry(&m);
    assert_eq!(e.name, "big4g.bin", "the name is past the two high halves");
    assert_eq!(e.unpacked_size, 4 * 1024 * 1024 * 1024 + 7);
    assert!(e.unpacked_size > u64::from(u32::MAX), "high_unp is in use");
    assert_eq!(e.data_len, 383, "this volume's fragment, not the member");
    assert!(e.split_before && !e.split_after, "the last fragment");
    // A last fragment carries the WHOLE-FILE CRC32, so it is not the
    // checksum of the 383 bytes in this volume.
    assert_ne!(
        e.file_crc,
        Some(crc32fast::hash(data_area(MAC_LARGE_TAIL, e)))
    );
    assert_eq!(e.file_crc, Some(1696784233));
}

/// Old-style `.rar`/`.r00`/`.r01` naming, which is how a split RAR4 set
/// is actually posted. The end-to-end claim: cut every volume's data
/// area out at the offset and length the mapper reported, concatenate in
/// volume order, and the result must check against the CRC32 the
/// archiver stamped on the last fragment.
#[test]
fn split_volume_fragments_reassemble_to_the_whole_file_crc() {
    for (label, vols) in [
        ("mac", [MAC_VOL0, MAC_VOL1, MAC_VOL2, MAC_VOL3]),
        ("win", [WIN_VOL0, WIN_VOL1, WIN_VOL2, WIN_VOL3]),
    ] {
        let mut whole = Vec::new();
        let mut last_crc = None;
        for (i, vol) in vols.iter().enumerate() {
            let m = map(None, vol);
            let e = only_entry(&m);
            assert_eq!(e.name, "split.bin", "{label} volume {i}");
            assert_eq!(
                e.unpacked_size, 2800,
                "{label} volume {i} declares the member"
            );
            assert_eq!(e.split_before, i > 0, "{label} volume {i} split_before");
            assert_eq!(e.split_after, i < 3, "{label} volume {i} split_after");
            // A non-final fragment's CRC32 describes its OWN bytes.
            if e.split_after {
                assert_eq!(
                    e.file_crc,
                    Some(crc32fast::hash(data_area(vol, e))),
                    "{label} volume {i} per-fragment CRC"
                );
            } else {
                last_crc = e.file_crc;
            }
            whole.extend_from_slice(data_area(vol, e));
        }
        assert_eq!(
            whole.len(),
            2800,
            "{label} fragments cover the member exactly"
        );
        assert_eq!(
            last_crc,
            Some(crc32fast::hash(&whole)),
            "{label} whole-file CRC"
        );
    }
}

/// The mode-3 run WITH a correction byte, which no Unix-written archive
/// reaches: rar on macOS writes the raw UTF-8 name as the fallback,
/// while WinRAR writes a code-page conversion whose bytes track the wide
/// low bytes at a constant offset. Before this fixture the branch had
/// never seen bytes an archiver produced.
#[test]
fn win_fullwidth_name_decodes_a_correction_run() {
    let want: String = (0..10u32)
        .map(|i| char::from_u32(0xFF21 + i).unwrap())
        .chain(".bin".chars())
        .collect();
    let m = map(None, WIN_FULLWIDTH);
    let e = only_entry(&m);
    assert_eq!(e.name, want);
    assert_eq!(e.unpacked_size, 1000);
}

/// The same branch at the `(len & 0x7f) + 2` ceiling: this 140-character
/// name codes as a 129-unit correction run followed by an 11-unit one,
/// so a run-length mask that is off by one loses characters here and
/// nowhere else.
#[test]
fn win_fullwidth_long_name_spans_two_correction_runs() {
    let want: String = (0..140u32)
        .map(|i| char::from_u32(0xFF21 + i % 26).unwrap())
        .chain(".bin".chars())
        .collect();
    let m = map(None, WIN_FULLWIDTH_LONG);
    let e = only_entry(&m);
    assert_eq!(e.name.chars().count(), 144);
    assert_eq!(e.name, want);
}

/// The Windows host writes a different host-OS byte in the same field
/// position; nothing downstream should notice.
#[test]
fn win_single_volume_store_maps_like_the_unix_one() {
    let m = map(None, WIN_STORE);
    let e = only_entry(&m);
    assert_eq!(e.name, "inner.bin");
    assert_eq!(e.data_len, 1000);
    assert_eq!(e.file_crc, Some(crc32fast::hash(data_area(WIN_STORE, e))));
}

/// `-hp` from a real archiver: `MHD_PASSWORD` on a plaintext main
/// header, then every block behind salt + AES padding. Our own writer
/// produces this shape too, which is exactly why it is worth checking
/// against one that does not share our assumptions.
#[test]
fn win_encrypted_headers_open_with_the_password() {
    let m = map(Some(PW), WIN_ENCHDR);
    let e = only_entry(&m);
    assert_eq!(e.name, "inner.bin");
    assert!(e.encrypted);
    assert_eq!(e.unpacked_size, 1000);
    assert_eq!(e.data_len, 1008, "ciphertext area = align16(plaintext)");
    assert!(matches!(
        e.crypt,
        Some(EntryCrypt::Rar4(Rar4Crypt { salt: Some(_) }))
    ));
}

#[test]
fn win_encrypted_headers_without_password_report_that() {
    let m = map(None, WIN_ENCHDR);
    assert_eq!(m.blocker, Some(MapBlocker::EncryptedHeaders));
    assert!(
        m.entries.is_empty(),
        "nothing past the main header is readable"
    );
}

/// An encrypted split set: one AES-128-CBC stream across four volumes,
/// with the salt repeated in every volume's header rather than carried
/// only by the first.
#[test]
fn win_encrypted_split_repeats_the_salt_and_pads_only_at_the_end() {
    let vols = [WIN_ENCVOL0, WIN_ENCVOL1, WIN_ENCVOL2, WIN_ENCVOL3];
    let mut total = 0u64;
    let mut salts = Vec::new();
    for (i, vol) in vols.iter().enumerate() {
        let m = map(Some(PW), vol);
        let e = only_entry(&m);
        assert_eq!(e.name, "split.bin");
        assert!(e.encrypted);
        assert_eq!(e.unpacked_size, 2800);
        assert_eq!(e.split_before, i > 0);
        assert_eq!(e.split_after, i < 3);
        let Some(EntryCrypt::Rar4(c)) = &e.crypt else {
            panic!("volume {i} carries no RAR4 key schedule")
        };
        salts.push(c.salt.expect("every volume repeats the salt"));
        total += e.data_len;
    }
    assert!(
        salts.windows(2).all(|w| w[0] == w[1]),
        "one salt for the set"
    );
    assert_eq!(
        total, 2800,
        "align16(2800) == 2800, so nothing is padded here"
    );
}

/// RAR4 stores the whole-file CRC32 of the PLAINTEXT even on an
/// encrypted member - the fact the finish pass adjudicates a password
/// against. Both sets below archive the same `split.bin`, one with `-p`
/// and one without, so the last fragment's CRC must be identical.
#[test]
fn encrypted_last_fragment_carries_the_plaintext_crc() {
    let plain = map(None, WIN_VOL3);
    let enc = map(Some(PW), WIN_ENCVOL3);
    let (p, c) = (only_entry(&plain), only_entry(&enc));
    assert!(!p.encrypted && c.encrypted);
    // Both are last fragments, so both carry the WHOLE-FILE value and
    // neither describes the handful of bytes in its own volume.
    assert_ne!(p.file_crc, Some(crc32fast::hash(data_area(WIN_VOL3, p))));
    assert_eq!(c.file_crc, p.file_crc);
    // And the plaintext set's value is checkable, which is what makes
    // "the encrypted one stores the PLAINTEXT crc" a measurement rather
    // than two unknowns agreeing.
    let whole: Vec<u8> = [WIN_VOL0, WIN_VOL1, WIN_VOL2, WIN_VOL3]
        .iter()
        .flat_map(|v| {
            let m = map(None, v);
            data_area(v, &m.entries[0]).to_vec()
        })
        .collect();
    assert_eq!(p.file_crc, Some(crc32fast::hash(&whole)));
}

/// A volume still arriving must never read as damaged. Every prefix of
/// every fixture, mapped at the volume's true declared length: the
/// parser may say "not yet", never `Corrupt`.
#[test]
fn no_prefix_of_a_healthy_volume_reads_as_corrupt() {
    let all: [(&str, &[u8], Option<&str>); 8] = [
        ("mac-store", MAC_STORE, None),
        ("mac-rr-comment", MAC_RR_COMMENT, None),
        ("mac-unicode", MAC_UNICODE, None),
        ("mac-large-tail", MAC_LARGE_TAIL, None),
        ("win-fullwidth-long", WIN_FULLWIDTH_LONG, None),
        ("win-oldvol.r00", WIN_VOL1, None),
        ("win-enchdr", WIN_ENCHDR, Some(PW)),
        ("win-encvol.r01", WIN_ENCVOL2, Some(PW)),
    ];
    for (label, vol, pw) in all {
        for n in 0..=vol.len() {
            let mut m = VolumeMapper::with_password(vol.len() as u64, pw.map(std::sync::Arc::from));
            m.feed(0, &vol[..n]);
            match &m.blocker {
                None | Some(MapBlocker::EncryptedHeaders) => {}
                other => panic!("{label} prefix {n}: {other:?}"),
            }
        }
    }
}
