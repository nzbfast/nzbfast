//! RAR4 header-framing tests: the CRC16 that makes a plaintext header
//! authoritative, and the cursor arithmetic over the geometry it
//! protects. A child module (the par2repair.rs pattern) so rar.rs stays
//! inside its size-gate entry; `super::*` reaches the private parser.

use super::*;
use fixtures::{V4_FIRST_BLOCK, restamp_v4_block};

fn payload(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// Codex sweep 10 Aug M5: a RAR4 header carries a CRC16 and nothing on
/// the PLAINTEXT path ever checked it, so damaged or crafted
/// name/flag/geometry bytes were taken as authoritative - and the
/// extractor turns that geometry straight into pwrite destinations.
/// RAR5 has always rejected its own CRC miss; RAR4 now matches.
///
/// Every byte of the header is walked so the check cannot be passing for
/// some narrower reason than "the header is intact", and the DATA area
/// is walked too: those bytes are outside the CRC by design and must
/// stay mappable, or the gate would be refusing the ordinary damaged
/// downloads that repair exists to fix.
#[test]
fn a_flipped_plaintext_v4_header_byte_is_refused() {
    let data = payload(4_000, 61);
    let good = fixtures::rar4_volume(&[("c.bin", 4_000, &data, false, false)]);
    let mut m = VolumeMapper::new(good.len() as u64);
    m.feed(0, &good);
    assert_eq!(m.blocker, None, "the untouched fixture must map");
    assert_eq!(m.entries.len(), 1);

    // The file header: block base 20, its own `hsize` bytes long.
    let base = V4_FIRST_BLOCK;
    let hsize = u16::from_le_bytes(good[base + 5..base + 7].try_into().unwrap()) as usize;
    for i in base..base + hsize {
        let mut bad = good.clone();
        bad[i] ^= 0x40;
        let mut m = VolumeMapper::new(bad.len() as u64);
        m.feed(0, &bad);
        // Either the CRC refuses it outright, or the flip broke the
        // framing badly enough that the walk never reaches the end
        // block. What must never happen is a COMPLETE, unblocked map
        // built on bytes the header's own CRC disowns - that map is what
        // the extractor pwrites through.
        assert!(
            m.blocker.is_some() || !m.complete,
            "header byte {} flipped and the volume still mapped clean",
            i - base
        );
    }
    // Restamping makes the same flip legitimate again - so the loop
    // above is the CRC talking, not a field-plausibility check.
    let mut restamped = good.clone();
    restamped[base + 25] = 0x33; // method byte: compressed
    restamp_v4_block(&mut restamped, base);
    let mut m = VolumeMapper::new(restamped.len() as u64);
    m.feed(0, &restamped);
    assert_eq!(
        m.blocker,
        Some(MapBlocker::NotStore),
        "an intact header must be read on its merits"
    );
    // Damage in the DATA area is what PAR2 repair is for; the header
    // gate must not swallow it.
    let mut hole = good.clone();
    let payload_at = base + hsize;
    hole[payload_at + 7] ^= 0xff;
    let mut m = VolumeMapper::new(hole.len() as u64);
    m.feed(0, &hole);
    assert_eq!(m.blocker, None, "damaged DATA must still map");
}

/// RAR4 >4 GiB store piece: `next` must use the full 64-bit packed size
/// (add_size + high_pack), not just the low 32 bits - otherwise the
/// cursor walks into the data area and ends in a Corrupt/NotStore
/// fallback.
#[test]
fn v4_large_piece_advances_cursor_past_full_data_len() {
    // Hand-build a v4 file header claiming a 5 GiB piece (no actual
    // data needed - we only check the returned cursor).
    let name = b"huge.bin";
    let data_len: u64 = 5 << 30; // 5 GiB
    let hsize = (7 + 4 + 4 + 1 + 4 + 4 + 1 + 1 + 2 + 4 + 8 + name.len()) as u16;
    let mut blk = Vec::new();
    blk.extend_from_slice(&0u16.to_le_bytes()); // head crc, stamped below
    blk.push(0x74);
    blk.extend_from_slice(&(0x8000u16 | 0x0100).to_le_bytes()); // add size + high fields
    blk.extend_from_slice(&hsize.to_le_bytes());
    blk.extend_from_slice(&((data_len & 0xFFFF_FFFF) as u32).to_le_bytes()); // add size lo
    blk.extend_from_slice(&((data_len & 0xFFFF_FFFF) as u32).to_le_bytes()); // unp lo
    blk.push(0); // host
    blk.extend_from_slice(&0u32.to_le_bytes()); // crc
    blk.extend_from_slice(&0u32.to_le_bytes()); // time
    blk.push(29); // unp_ver
    blk.push(0x30); // store
    blk.extend_from_slice(&(name.len() as u16).to_le_bytes());
    blk.extend_from_slice(&0u32.to_le_bytes()); // attr
    blk.extend_from_slice(&((data_len >> 32) as u32).to_le_bytes()); // high_pack
    blk.extend_from_slice(&((data_len >> 32) as u32).to_le_bytes()); // high_unp
    blk.extend_from_slice(name);
    fixtures::stamp_v4_head_crc(&mut blk);
    let base = 20u64;
    match parse_block_v4(&blk, base) {
        BlockResult::File { entry, next } => {
            assert_eq!(entry.data_len, data_len);
            assert_eq!(entry.unpacked_size, data_len);
            assert_eq!(
                next,
                base + hsize as u64 + data_len,
                "cursor must skip the FULL piece"
            );
        }
        _ => panic!("expected a file block"),
    }
}

/// Found by the RAR4 plaintext fuzz half that landed with the M5 CRC
/// gate: `high_pack = 0xFFFF_FFFF` puts the declared piece within a few
/// bytes of `u64::MAX`, and summing it with the block's own offset
/// panicked in debug and wrapped in release. A wrapped cursor is the
/// shape that walks the parse loop backwards over itself.
///
/// Not academic just because the CRC gate now stands in front of it: a
/// poster stamps a correct CRC over whatever fields they like. The twin
/// of the test above - same field, the value it cannot carry.
#[test]
fn a_v4_piece_declaring_the_whole_address_space_is_refused() {
    let name = b"huge.bin";
    let hsize = (7 + 4 + 4 + 1 + 4 + 4 + 1 + 1 + 2 + 4 + 8 + name.len()) as u16;
    let mut blk = Vec::new();
    blk.extend_from_slice(&0u16.to_le_bytes()); // head crc, stamped below
    blk.push(0x74);
    blk.extend_from_slice(&(0x8000u16 | 0x0100).to_le_bytes()); // add size + high fields
    blk.extend_from_slice(&hsize.to_le_bytes());
    blk.extend_from_slice(&u32::MAX.to_le_bytes()); // add size lo
    blk.extend_from_slice(&u32::MAX.to_le_bytes()); // unp lo
    blk.push(0); // host
    blk.extend_from_slice(&0u32.to_le_bytes()); // crc
    blk.extend_from_slice(&0u32.to_le_bytes()); // time
    blk.push(29); // unp_ver
    blk.push(0x30); // store
    blk.extend_from_slice(&(name.len() as u16).to_le_bytes());
    blk.extend_from_slice(&0u32.to_le_bytes()); // attr
    blk.extend_from_slice(&u32::MAX.to_le_bytes()); // high_pack
    blk.extend_from_slice(&u32::MAX.to_le_bytes()); // high_unp
    blk.extend_from_slice(name);
    fixtures::stamp_v4_head_crc(&mut blk);
    assert!(
        matches!(parse_block_v4(&blk, 20), BlockResult::Corrupt(_)),
        "a piece that cannot be addressed must be refused, not summed"
    );
}

/// TODO 159 item 4 / torture round 4 finding 4: a RAR 2.x unix-owner
/// sub-block declares an owner and a group name size in its fixed part
/// but stores the names themselves in its DATA area, past `head_size` -
/// and the CRC16 covers them, because unrar reads both into the same raw
/// header buffer before checksumming it. Checksumming only `head_size`
/// called the block corrupt, which on the disk side (the vendored rars
/// fork) refused the whole archive with "expected 0x1fc3, got 0x974d".
#[test]
fn a_unix_owner_subblock_is_checksummed_over_the_names_in_its_data_area() {
    // The sub-block out of markokr/rarfile's `rar2-unix-owner.rar`,
    // verbatim: head_crc 0x1fc3, type 0x77, LONG_BLOCK, head_size 18,
    // data size 8, sub type UO_HEAD, level 0, owner "root", group "root".
    let block: [u8; 26] = [
        0xc3, 0x1f, 0x77, 0x00, 0x80, 0x12, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x04,
        0x00, 0x04, 0x00, b'r', b'o', b'o', b't', b'r', b'o', b'o', b't',
    ];
    assert!(
        matches!(v4_header_crc(&block), V4HeaderCrc::Ok),
        "the names are part of the covered range"
    );
    assert!(
        matches!(parse_block_v4(&block, 20), BlockResult::Skip { .. }),
        "a sub-block we do not read is skipped, not condemned"
    );

    // Stopping at `head_size` is the range that broke it, and the parser
    // must ask for the missing bytes rather than rule on them.
    assert!(matches!(v4_header_crc(&block[..18]), V4HeaderCrc::NeedMore));
    assert!(matches!(
        parse_block_v4(&block[..18], 20),
        BlockResult::NeedMore
    ));

    // Extended, not exempted: the names are checksummed for real.
    let mut damaged = block;
    damaged[18] ^= 0x20;
    assert!(matches!(v4_header_crc(&damaged), V4HeaderCrc::Mismatch));
    assert!(matches!(
        parse_block_v4(&damaged, 20),
        BlockResult::Corrupt("v4 header CRC mismatch")
    ));

    // The extension is keyed on the sub type: any other sub-block keeps
    // the plain `head_size` range, payload uncovered.
    let mut other = block;
    other[11..13].copy_from_slice(&0x0100u16.to_le_bytes());
    assert!(matches!(v4_header_crc(&other), V4HeaderCrc::Mismatch));
}

/// The other end of the same range question: a file header carrying an
/// old-style comment is checksummed over its FIXED part only, stopping
/// after the name (and salt), because the comment area that follows is
/// outside the CRC. `name_size` is at +26 - +28 is the attribute word, and
/// reading that one instead made every commented header miss its CRC and
/// be judged corrupt.
#[test]
fn a_commented_file_header_is_checksummed_up_to_the_comment_area() {
    let name = b"c.txt";
    let comment = b"note!!";
    let hsize = (32 + name.len() + comment.len()) as u16;
    let mut blk = Vec::new();
    blk.extend_from_slice(&0u16.to_le_bytes()); // head crc, stamped below
    blk.push(0x74);
    blk.extend_from_slice(&(0x8000u16 | 0x0008).to_le_bytes()); // long block + comment
    blk.extend_from_slice(&hsize.to_le_bytes());
    blk.extend_from_slice(&0u32.to_le_bytes()); // pack size
    blk.extend_from_slice(&0u32.to_le_bytes()); // unp size
    blk.push(0); // host
    blk.extend_from_slice(&0u32.to_le_bytes()); // crc
    blk.extend_from_slice(&0u32.to_le_bytes()); // time
    blk.push(20); // unp_ver
    blk.push(0x30); // store
    blk.extend_from_slice(&(name.len() as u16).to_le_bytes());
    blk.extend_from_slice(&0xdead_beefu32.to_le_bytes()); // attr: NOT the name size
    blk.extend_from_slice(name);
    blk.extend_from_slice(comment);
    let covered = 32 + name.len();
    let crc = (crc32fast::hash(&blk[2..covered]) & 0xffff) as u16;
    blk[..2].copy_from_slice(&crc.to_le_bytes());
    assert!(matches!(v4_header_crc(&blk), V4HeaderCrc::Ok));

    // Damage inside the comment area is outside the covered range, so the
    // header stays authoritative - that is what the short range means.
    let mut commented = blk.clone();
    commented[covered] ^= 0x40;
    assert!(matches!(v4_header_crc(&commented), V4HeaderCrc::Ok));

    // Damage to the name is inside it.
    let mut renamed = blk.clone();
    renamed[32] ^= 0x40;
    assert!(matches!(v4_header_crc(&renamed), V4HeaderCrc::Mismatch));
}

/// The `hsize < 13` bound on the two fixed-13 comment arms, pinned by
/// the two verdicts the panic hid behind (landed as `868b2603`; its own
/// test drives the reduced crash input, which is unstamped and so cannot
/// tell one wrong answer from another).
///
/// The CRCs here are STAMPED, so each assertion fails against a specific
/// alternative fix rather than against a coin flip:
///
/// - stamped over the bytes the block declares, a clamp to `head_size` -
///   what the vendored fork's `.min(full_end)` does, and what this port
///   kept only on the file-header arm - would answer `Ok` over a range
///   no writer ever checksummed;
/// - stamped over 13 with the next block's bytes behind it, the
///   unbounded range would answer `Ok` over a byte that is not this
///   header's, which is the half of the bug no panic ever showed.
///
/// The verdict is `Mismatch` and not `NeedMore` because `head_size` is
/// stored IN the header and no later byte can raise it: `NeedMore` would
/// park the parser on bytes that can never come (the trap
/// `parse_block_v4_enc_with` names), and it is not a password verdict
/// there, so a wrong `-hp` password whose random `head_size` landed
/// under 13 would walk past the CRC oracle.
#[test]
fn a_comment_block_shorter_than_its_fixed_crc_range_is_refused() {
    // hsize 12: one byte short of the 13 the CRC covers.
    let short = |btype: u8, flags: u16| -> Vec<u8> {
        let mut h = vec![0u8; 12];
        h[2] = btype;
        h[3..5].copy_from_slice(&flags.to_le_bytes());
        h[5..7].copy_from_slice(&12u16.to_le_bytes());
        h
    };
    const MHD_COMMENT: u16 = 0x0002;
    for (btype, flags) in [(0x75u8, 0u16), (0x73u8, MHD_COMMENT)] {
        let mut h = short(btype, flags);
        let crc = (crc32fast::hash(&h[2..12]) & 0xffff) as u16;
        h[..2].copy_from_slice(&crc.to_le_bytes());
        assert!(
            matches!(v4_header_crc(&h), V4HeaderCrc::Mismatch),
            "type {btype:#04x}: a block too short for its own CRC range is malformed"
        );
        assert!(matches!(
            parse_block_v4(&h, 20),
            BlockResult::Corrupt("v4 header CRC mismatch")
        ));

        // Same block, more bytes behind it: the 13th byte belongs to
        // whatever follows, so the verdict must not change.
        let mut trailing = short(btype, flags);
        trailing.extend_from_slice(&[0xa5; 8]);
        let crc = (crc32fast::hash(&trailing[2..13]) & 0xffff) as u16;
        trailing[..2].copy_from_slice(&crc.to_le_bytes());
        assert!(
            matches!(v4_header_crc(&trailing), V4HeaderCrc::Mismatch),
            "type {btype:#04x}: the covered range must not run into the next block"
        );
    }
}
