use super::*;

use fixtures::{V4_FIRST_BLOCK, restamp_v4_block};

fn payload(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// The signature alone is not evidence, and this is the check that
/// says so. Both magics occur as constants inside ordinary programs,
/// so a self-extractor gate built on a substring match claims them -
/// 25 of 1,105 real binaries, binaries this project itself ships
/// included (TODO 159 item 7). The header CRC is what separates
/// "these bytes appear here" from "an archive begins here".
#[test]
fn a_signature_is_only_an_archive_with_a_valid_main_header_behind_it() {
    let data = payload(2_048, 9);
    // The stored header checksum's own bytes, per dialect: RAR5 puts a
    // CRC32 straight after its 8-byte signature, RAR4 a CRC16 after
    // its 7-byte one. Corrupting THOSE and nothing else is what isolates
    // the checksum from every other check in here.
    for (vol, crc_at) in [
        (
            fixtures::rar5_volume(&[("a.bin", 0, &data, false, false)]),
            8,
        ),
        (
            fixtures::rar4_volume(&[("a.bin", 0, &data, false, false)]),
            7,
        ),
    ] {
        assert!(archive_starts_here(&vol), "a real volume must confirm");

        // The magic with nothing behind it: what a program's own code
        // looks like, and what used to be claimed.
        assert!(!archive_starts_here(&vol[..8.min(vol.len())]));
        let mut bare = vol[..8].to_vec();
        bare.extend([0u8; 128]);
        assert!(!archive_starts_here(&bare), "magic + zeroes is not one");

        // Header intact, signature intact, stored checksum wrong. No
        // size, type or bounds check can see this one - only the CRC.
        let mut damaged = vol.clone();
        damaged[crc_at] ^= 0xff;
        assert!(
            !archive_starts_here(&damaged),
            "a header whose stored checksum disagrees is not an archive"
        );

        // Truncation answers false rather than guessing - which is why
        // a caller scanning a bounded window must read past its edge.
        assert!(!archive_starts_here(&vol[..12]));

        // Shifted by one: the signature has to be at byte 0.
        let mut shifted = vec![0u8; 1];
        shifted.extend(&vol);
        assert!(!archive_starts_here(&shifted));
    }
    assert!(!archive_starts_here(b"not a rar at all"));
    assert!(!archive_starts_here(&[]));
}

#[test]
fn needs_password_on_disk_detection() {
    let dir = std::env::temp_dir().join(format!("nzbkit-rar-pw-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let write = |name: &str, bytes: &[u8]| {
        let p = dir.join(name);
        std::fs::write(&p, bytes).unwrap();
        p
    };
    // Encrypted headers (RAR4 MHD_PASSWORD) → password required.
    assert!(needs_password(&write(
        "enc.rar",
        &fixtures::rar4_encrypted_headers(64)
    )));
    // Plain store volume → no.
    let store = fixtures::rar4_volume(&[("a.bin", 4, b"data", false, false)]);
    assert!(!needs_password(&write("plain.rar", &store)));
    // Readable headers but the file's data is encrypted: LHD_PASSWORD
    // (0x0004) in the file-header flags (sig 7 + main 13 = block base
    // 20; flags at +3) → password required.
    let mut pwfile = store.clone();
    pwfile[23] |= 0x04;
    restamp_v4_block(&mut pwfile, V4_FIRST_BLOCK);
    assert!(needs_password(&write("pwfile.rar", &pwfile)));
    // Compressed-but-not-encrypted (method byte at block base + 25)
    // must NOT ask for a password - unrar unpacks it alone.
    let mut comp = store.clone();
    comp[45] = 0x33;
    restamp_v4_block(&mut comp, V4_FIRST_BLOCK);
    assert!(!needs_password(&write("comp.rar", &comp)));
    // Not a RAR / unreadable → no (nothing to unlock).
    assert!(!needs_password(&write("junk.rar", b"not a rar at all")));
    assert!(!needs_password(&dir.join("missing.rar")));
    let _ = std::fs::remove_dir_all(&dir);
}

/// The discriminator the extraction ladder's `-hp` shortcut rests on:
/// "is the password we hold any use to the STREAMING path". Both
/// formats now answer the same way - opaque with no password, and
/// parseable with the right one - so neither is diverted to a disk
/// read it no longer needs. (RAR4 `-hp` used to answer yes-opaque
/// whatever it was passed, because header decryption was unimplemented.)
#[test]
fn headers_encrypted_to_separates_hp_from_a_usable_password() {
    let dir = std::env::temp_dir().join(format!("nzbkit-hdrenc-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let write = |name: &str, bytes: &[u8]| {
        let p = dir.join(name);
        std::fs::write(&p, bytes).unwrap();
        p
    };
    let rar4 = write("hp4.rar", V4_ENC_HDRS);
    assert!(headers_encrypted_to(&rar4, None));
    assert!(
        !headers_encrypted_to(&rar4, Some(PW)),
        "RAR4 -hp decrypts in-stream now - it must not be diverted to disk"
    );
    // Same rule as RAR5 below: a wrong password is a BadPassword
    // blocker, not an opaque one.
    assert!(!headers_encrypted_to(&rar4, Some("nope")));

    let rar5 = write("hp5.rar", ENC_HDRS);
    assert!(headers_encrypted_to(&rar5, None));
    assert!(
        !headers_encrypted_to(&rar5, Some(PW)),
        "RAR5 -hp decrypts in-stream - it must not be diverted to disk"
    );
    // A wrong password is a BadPassword blocker, not an opaque one:
    // reading the volumes off disk would not help either, so the
    // streaming path keeps it and reports the real reason.
    assert!(!headers_encrypted_to(&rar5, Some("nope")));

    // Nothing encrypted, and a non-archive: never divert.
    let store = fixtures::rar4_volume(&[("a.bin", 4, b"data", false, false)]);
    assert!(!headers_encrypted_to(&write("plain.rar", &store), Some(PW)));
    assert!(!headers_encrypted_to(
        &write("junk.rar", b"not a rar"),
        Some(PW)
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Feed a volume to a mapper in shuffled article-sized chunks.
fn feed_shuffled(m: &mut VolumeMapper, vol: &[u8], art: usize, seed: u64) {
    let mut idx: Vec<usize> = (0..vol.len().div_ceil(art)).collect();
    // Tiny LCG shuffle.
    let mut state = seed;
    for i in (1..idx.len()).rev() {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        idx.swap(i, (state >> 33) as usize % (i + 1));
    }
    for i in idx {
        let s = i * art;
        let e = (s + art).min(vol.len());
        m.feed(s as u64, &vol[s..e]);
    }
}

#[test]
fn v5_single_file_maps_fully() {
    let data = payload(100_000, 7);
    let vol = fixtures::rar5_volume(&[("movie.mkv", 100_000, &data, false, false)]);
    let mut m = VolumeMapper::new(vol.len() as u64);
    assert!(m.feed(0, &vol));
    assert_eq!(m.version, Some(RarVersion::V5));
    assert!(m.complete);
    assert_eq!(m.blocker, None);
    assert_eq!(m.entries.len(), 1);
    let e = &m.entries[0];
    assert_eq!(e.name, "movie.mkv");
    assert_eq!(e.method, Method::Store);
    assert_eq!(e.data_len, 100_000);
    // The data area must be exactly the payload.
    let off = e.data_off as usize;
    assert_eq!(&vol[off..off + 100_000], &data[..]);
    // map_span round-trip.
    let hits = m.map_span(e.data_off + 10, 50);
    assert_eq!(hits, vec![(0, 10, 0, 50)]);
}

#[test]
fn v5_out_of_order_articles() {
    let data = payload(300_000, 3);
    let vol = fixtures::rar5_volume(&[("big.bin", 300_000, &data, false, false)]);
    for seed in 1..6u64 {
        let mut m = VolumeMapper::new(vol.len() as u64);
        feed_shuffled(&mut m, &vol, 7000, seed);
        assert!(m.complete, "seed {seed}");
        assert_eq!(m.entries.len(), 1);
        assert_eq!(m.entries[0].data_len, 300_000);
    }
}

#[test]
fn v5_multi_file_volume() {
    let a = payload(50_000, 1);
    let b = payload(80_000, 2);
    let vol = fixtures::rar5_volume(&[
        ("a.bin", 50_000, &a, false, false),
        ("b.bin", 80_000, &b, false, false),
    ]);
    let mut m = VolumeMapper::new(vol.len() as u64);
    // Feed only the first 4 KB: should parse main + file a's header.
    m.feed(0, &vol[..4096]);
    assert_eq!(m.entries.len(), 1);
    assert!(!m.complete);
    // b's header sits after a's 50 KB data area - feed that region.
    let need = m.mapped_through() as usize;
    m.feed(need as u64, &vol[need..(need + 4096).min(vol.len())]);
    assert_eq!(m.entries.len(), 2);
    assert_eq!(m.entries[1].name, "b.bin");
    let off = m.entries[1].data_off as usize;
    assert_eq!(&vol[off..off + 80_000], &b[..]);
}

#[test]
fn v5_split_series_resolves_bases() {
    let total = payload(250_000, 9);
    let p1 = &total[..100_000];
    let p2 = &total[100_000..200_000];
    let p3 = &total[200_000..];
    let v1 = fixtures::rar5_volume(&[("film.mkv", 250_000, p1, false, true)]);
    let v2 = fixtures::rar5_volume(&[("film.mkv", 250_000, p2, true, true)]);
    let v3 = fixtures::rar5_volume(&[("film.mkv", 250_000, p3, true, false)]);
    let mut m1 = VolumeMapper::new(v1.len() as u64);
    let mut m2 = VolumeMapper::new(v2.len() as u64);
    let mut m3 = VolumeMapper::new(v3.len() as u64);
    m1.feed(0, &v1);
    m2.feed(0, &v2);
    m3.feed(0, &v3);
    let map = ArchiveMap::resolve(&[&m1, &m2, &m3]);
    assert_eq!(map.bases[&(0, 0)], 0);
    assert_eq!(map.bases[&(1, 0)], 100_000);
    assert_eq!(map.bases[&(2, 0)], 200_000);
}

#[test]
fn bases_resolve_from_headers_alone_not_completeness() {
    // Volume 1: only its HEADER bytes fed (end block still in flight -
    // the 35 GB regression: waiting on completeness stalls resolution
    // behind every volume's last article). Volume 2's base must still
    // resolve from vol 1's parsed piece length.
    let total = payload(200_000, 6);
    let v1 = fixtures::rar5_volume_n(&[("m.mkv", 200_000, &total[..120_000], false, true)], 0);
    let v2 = fixtures::rar5_volume_n(&[("m.mkv", 200_000, &total[120_000..], true, false)], 1);
    let mut m1 = VolumeMapper::new(v1.len() as u64);
    m1.feed(0, &v1[..4096]); // header only
    assert!(!m1.complete && m1.entries.len() == 1);
    let mut m2 = VolumeMapper::new(v2.len() as u64);
    m2.feed(0, &v2[..4096]);
    let map = ArchiveMap::resolve(&[&m1, &m2]);
    assert_eq!(map.bases[&(1, 0)], 120_000, "vol2 base from vol1 header");
}

#[test]
fn v5_bases_wait_for_missing_volume() {
    // Three volumes, only the LAST parsed. Its piece ends the file,
    // so its base is `unpacked_size - data_len` from its own header
    // alone - no chain, no neighbours. (This used to assert the
    // opposite: forward-only resolution could place nothing until
    // volume 1 arrived, which is what stalled obfuscated season
    // packs.)
    let total = payload(300_000, 4);
    let v1 = fixtures::rar5_volume(&[("x.bin", 300_000, &total[..100_000], false, true)]);
    let v2 = fixtures::rar5_volume(&[("x.bin", 300_000, &total[100_000..200_000], true, true)]);
    let v3 = fixtures::rar5_volume(&[("x.bin", 300_000, &total[200_000..], true, false)]);
    let m1 = VolumeMapper::new(v1.len() as u64); // never fed!
    let m2 = VolumeMapper::new(v2.len() as u64); // never fed!
    let mut m3 = VolumeMapper::new(v3.len() as u64);
    m3.feed(0, &v3);
    let map = ArchiveMap::resolve(&[&m1, &m2, &m3]);
    assert_eq!(map.bases.get(&(2, 0)).copied(), Some(200_000));
    assert!(!map.contradiction);
    // The MIDDLE piece is still unplaceable on its own - it is
    // neither the file's head nor its tail, so it genuinely needs a
    // neighbour. That is the limit the tail seed does not remove.
    let mut m2 = VolumeMapper::new(v2.len() as u64);
    m2.feed(0, &v2);
    let m3_empty = VolumeMapper::new(v3.len() as u64); // never fed!
    let map = ArchiveMap::resolve(&[&m1, &m2, &m3_empty]);
    assert!(map.bases.is_empty(), "{:?}", map.bases);
}

/// The tail seed walks BACKWARD: once the final piece is anchored,
/// each earlier piece of the same file follows from it, so a set
/// resolves from its end even with volume 0 still missing.
#[test]
fn v5_bases_walk_backward_from_the_final_piece() {
    let total = payload(300_000, 6);
    let v1 = fixtures::rar5_volume(&[("x.bin", 300_000, &total[..100_000], false, true)]);
    let v2 = fixtures::rar5_volume(&[("x.bin", 300_000, &total[100_000..200_000], true, true)]);
    let v3 = fixtures::rar5_volume(&[("x.bin", 300_000, &total[200_000..], true, false)]);
    let m1 = VolumeMapper::new(v1.len() as u64); // never fed!
    let mut m2 = VolumeMapper::new(v2.len() as u64);
    let mut m3 = VolumeMapper::new(v3.len() as u64);
    m2.feed(0, &v2);
    m3.feed(0, &v3);
    let map = ArchiveMap::resolve(&[&m1, &m2, &m3]);
    assert_eq!(map.bases.get(&(2, 0)).copied(), Some(200_000));
    assert_eq!(
        map.bases.get(&(1, 0)).copied(),
        Some(100_000),
        "backward step"
    );
    assert!(!map.contradiction);
}

/// Headers that disagree with themselves: the piece in volume 2 is
/// reachable forward from volume 1 and backward from volume 3, and
/// the two answers differ. Nothing may be placed on a guess, so the
/// map reports the contradiction and the caller demotes.
#[test]
fn v5_bases_flag_a_self_contradictory_chain() {
    let total = payload(300_000, 8);
    // Volume 2 claims a piece longer than the gap the other two
    // leave for it.
    let v1 = fixtures::rar5_volume(&[("x.bin", 300_000, &total[..100_000], false, true)]);
    let v2 = fixtures::rar5_volume(&[("x.bin", 300_000, &total[..150_000], true, true)]);
    let v3 = fixtures::rar5_volume(&[("x.bin", 300_000, &total[200_000..], true, false)]);
    let mut ms = Vec::new();
    for v in [&v1, &v2, &v3] {
        let mut m = VolumeMapper::new(v.len() as u64);
        m.feed(0, v);
        ms.push(m);
    }
    let refs: Vec<&VolumeMapper> = ms.iter().collect();
    let map = ArchiveMap::resolve(&refs);
    assert!(map.contradiction, "disagreeing neighbours must be reported");
}

#[test]
fn v4_single_and_split() {
    let data = payload(120_000, 5);
    let vol = fixtures::rar4_volume(&[("old.avi", 120_000, &data, false, false)]);
    let mut m = VolumeMapper::new(vol.len() as u64);
    m.feed(0, &vol);
    assert_eq!(m.version, Some(RarVersion::V4));
    assert!(m.complete);
    assert_eq!(m.entries.len(), 1);
    assert_eq!(m.entries[0].method, Method::Store);
    let off = m.entries[0].data_off as usize;
    assert_eq!(&vol[off..off + 120_000], &data[..]);

    // Split pair.
    let p1 = &data[..60_000];
    let p2 = &data[60_000..];
    let v1 = fixtures::rar4_volume(&[("old.avi", 120_000, p1, false, true)]);
    let v2 = fixtures::rar4_volume(&[("old.avi", 120_000, p2, true, false)]);
    let mut m1 = VolumeMapper::new(v1.len() as u64);
    let mut m2 = VolumeMapper::new(v2.len() as u64);
    m1.feed(0, &v1);
    m2.feed(0, &v2);
    assert!(m1.entries[0].split_after && !m1.entries[0].split_before);
    assert!(m2.entries[0].split_before && !m2.entries[0].split_after);
    let map = ArchiveMap::resolve(&[&m1, &m2]);
    assert_eq!(map.bases[&(1, 0)], 60_000);
}

#[test]
fn compressed_flagged_not_store() {
    // Method bits nonzero → Compressed → blocker NotStore.
    let data = payload(10_000, 8);
    let mut vol = fixtures::rar5_volume(&[("c.bin", 10_000, &data, false, false)]);
    // Patch compression_info in the file header: find the name and walk
    // back… simpler: rebuild via a tweaked writer is overkill - craft by
    // scanning for method vint is brittle. Instead test v4 (fixed
    // layout): method byte 0x33 = compressed.
    let mut v4 = fixtures::rar4_volume(&[("c.bin", 10_000, &data, false, false)]);
    // method byte offset: sig 7 + main 13 + 11 (intro+add) + 4+1+4+4+1 = 49
    let m_off = 7 + 13 + 11 + 14;
    assert_eq!(v4[m_off], 0x30);
    v4[m_off] = 0x33;
    restamp_v4_block(&mut v4, V4_FIRST_BLOCK);
    let mut m = VolumeMapper::new(v4.len() as u64);
    m.feed(0, &v4);
    assert_eq!(m.blocker, Some(MapBlocker::NotStore));

    // And RAR5 header corruption is caught by the CRC.
    vol[10] ^= 0xff;
    let mut m5 = VolumeMapper::new(vol.len() as u64);
    m5.feed(0, &vol);
    assert!(matches!(m5.blocker, Some(MapBlocker::Corrupt(_))));
}

/// A RAR4 file header carrying `field` verbatim as its name area and
/// no data area, so headers pack back to back. `extra_flags` is OR'd
/// into the block flags (FHD_UNICODE for the packed-name tests).
fn v4_file_header(field: &[u8], extra_flags: u16) -> Vec<u8> {
    let hsize = (32 + field.len()) as u16;
    let mut blk = Vec::new();
    blk.extend_from_slice(&0u16.to_le_bytes()); // head crc (unchecked)
    blk.push(0x74);
    blk.extend_from_slice(&(0x8000u16 | extra_flags).to_le_bytes()); // add size present
    blk.extend_from_slice(&hsize.to_le_bytes());
    blk.extend_from_slice(&0u32.to_le_bytes()); // add size: no data area
    blk.extend_from_slice(&0u32.to_le_bytes()); // unp size
    blk.push(0); // host
    blk.extend_from_slice(&0u32.to_le_bytes()); // crc
    blk.extend_from_slice(&0u32.to_le_bytes()); // time
    blk.push(29); // unp_ver
    blk.push(0x30); // store
    blk.extend_from_slice(&(field.len() as u16).to_le_bytes());
    blk.extend_from_slice(&0u32.to_le_bytes()); // attr
    blk.extend_from_slice(field);
    fixtures::stamp_v4_head_crc(&mut blk);
    blk
}

/// Wrap raw blocks in a RAR4 signature + main header + ENDARC.
fn v4_volume_of(blocks: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(SIG4);
    let mut main = Vec::new();
    main.extend_from_slice(&0u16.to_le_bytes()); // main head crc
    main.push(0x73);
    main.extend_from_slice(&0u16.to_le_bytes()); // flags
    main.extend_from_slice(&13u16.to_le_bytes());
    main.extend_from_slice(&[0u8; 6]); // reserved
    fixtures::stamp_v4_head_crc(&mut main);
    out.extend_from_slice(&main);
    out.extend_from_slice(blocks);
    let mut end = Vec::new();
    end.extend_from_slice(&0u16.to_le_bytes()); // ENDARC
    end.push(0x7b);
    end.extend_from_slice(&0u16.to_le_bytes());
    end.extend_from_slice(&7u16.to_le_bytes());
    fixtures::stamp_v4_head_crc(&mut end);
    out.extend_from_slice(&end);
    out
}

/// A downloaded RAR4 volume must not turn into many times its own size
/// in resident memory through its FILE NAMES. The packed-unicode
/// decoder's ceiling used to be counted per HEADER, which a 70-byte
/// header reaches on its own: 200 of them decoded to ~88x the volume,
/// so a ~100 MB volume in any NZB meant ~9 GB resident. Legitimate
/// FHD_UNICODE names must still decode exactly.
#[test]
fn v4_unicode_names_cannot_amplify_the_volume() {
    // Hostile: empty ASCII fallback, high byte 0x08, then 36 bytes of
    // 0xFF - every 2-bit mode is 3 (a run), every run is the maximum
    // 129 units, and every unit is a 3-byte UTF-8 character.
    let mut field = vec![0u8, 0x08];
    field.extend_from_slice(&[0xFFu8; 36]);
    let hdr = v4_file_header(&field, FHD_UNICODE);
    assert_eq!(hdr.len(), 70);
    let mut blocks = Vec::new();
    for _ in 0..200 {
        blocks.extend_from_slice(&hdr);
    }
    let vol = v4_volume_of(&blocks);
    let mut m = VolumeMapper::new(vol.len() as u64);
    m.feed(0, &vol);
    assert_eq!(m.entries.len(), 200);
    let decoded: usize = m.entries.iter().map(|e| e.name.len()).sum();
    assert!(
        decoded <= 3 * vol.len(),
        "names decoded to {decoded} bytes from a {}-byte volume",
        vol.len()
    );

    // Good case: a real FHD_UNICODE name, through every mode a writer
    // uses - a mode-3 run copied from the ASCII fallback, a mode-2
    // literal for the non-ASCII character, then a second run.
    let mut good = b"My.Long.Show.S01E01.e.mkv".to_vec();
    good.push(0); // separator
    good.push(0); // high byte
    good.extend_from_slice(&[0xEC, 18, 0xE9, 0x00, 2]);
    let vol = v4_volume_of(&v4_file_header(&good, FHD_UNICODE));
    let mut m = VolumeMapper::new(vol.len() as u64);
    m.feed(0, &vol);
    assert_eq!(m.entries.len(), 1);
    assert_eq!(m.entries[0].name, "My.Long.Show.S01E01.é.mkv");
}

/// A stream of back-to-back file headers must stop being mapped rather
/// than growing the retained entry list at line rate - and it must stop
/// with NotStore, so the job still materializes its volumes and hands
/// them to unrar instead of failing outright.
#[test]
fn v4_entry_flood_stops_mapping_without_failing_the_job() {
    let hdr = v4_file_header(b"", 0);
    assert_eq!(hdr.len(), 32);
    let mut blocks = Vec::with_capacity(hdr.len() * (MAX_ENTRIES + 50));
    for _ in 0..MAX_ENTRIES + 50 {
        blocks.extend_from_slice(&hdr);
    }
    let vol = v4_volume_of(&blocks);
    let mut m = VolumeMapper::new(vol.len() as u64);
    // Article-sized feeds, so the parse window stays small.
    for s in (0..vol.len()).step_by(4096) {
        let e = (s + 4096).min(vol.len());
        m.feed(s as u64, &vol[s..e]);
    }
    assert_eq!(m.blocker, Some(MapBlocker::NotStore));
    assert!(!m.complete);
    assert!(
        m.entries.len() <= MAX_ENTRIES,
        "{} entries retained",
        m.entries.len()
    );
    // Both mapper preconditions of the extractor's chase attach still
    // say no (RAR5 only, exactly one entry), so this routes to
    // materialize + unrar rather than to a chase worker.
    assert_eq!(m.version, Some(RarVersion::V4));
    assert_ne!(m.entries.len(), 1);

    // A real multi-file store volume is untouched by the cap.
    let a = payload(1_000, 1);
    let b = payload(2_000, 2);
    let c = payload(3_000, 3);
    let ok = fixtures::rar4_volume(&[
        ("a.bin", 1_000, &a, false, false),
        ("b.bin", 2_000, &b, false, false),
        ("c.bin", 3_000, &c, false, false),
    ]);
    let mut m = VolumeMapper::new(ok.len() as u64);
    m.feed(0, &ok);
    assert_eq!(m.blocker, None);
    assert!(m.complete);
    assert_eq!(m.entries.len(), 3);
    assert_eq!(m.entries[2].name, "c.bin");
    let off = m.entries[2].data_off as usize;
    assert_eq!(&ok[off..off + 3_000], &c[..]);
}

/// RAR5 extra-area record with a hostile size near 2^64: the record
/// walk must terminate (the wrapping add mapped the cursor onto
/// itself - an infinite loop holding the extractor's global lock).
#[test]
fn v5_hostile_extra_record_size_terminates() {
    // File header with an extra area whose record size vint is huge.
    let mut extra = vec![0xFF; 9];
    extra.push(0x7F); // vint ≈ 2^63+ - record "size"
    extra.push(0x01); // record type: file encryption
    let mut body = Vec::new();
    let mut hdr = Vec::new();
    // type 2 (file), flags 0x03 (extra + data), extra size, data size
    fn vint_enc(mut v: u64, out: &mut Vec<u8>) {
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
    vint_enc(2, &mut hdr);
    vint_enc(0x03, &mut hdr);
    vint_enc(extra.len() as u64, &mut hdr); // extra size
    vint_enc(4, &mut hdr); // data size
    vint_enc(0, &mut body); // file flags
    vint_enc(100, &mut body); // unpacked
    vint_enc(0, &mut body); // attrs
    vint_enc(0, &mut body); // comp info: store
    vint_enc(0, &mut body); // host
    vint_enc(4, &mut body); // name len
    body.extend_from_slice(b"x.mk");
    hdr.extend_from_slice(&body);
    hdr.extend_from_slice(&extra);
    let mut sized = Vec::new();
    vint_enc(hdr.len() as u64, &mut sized);
    let mut blk = Vec::new();
    let mut crc = crc32fast::Hasher::new();
    crc.update(&sized);
    crc.update(&hdr);
    blk.extend_from_slice(&crc.finalize().to_le_bytes());
    blk.extend_from_slice(&sized);
    blk.extend_from_slice(&hdr);
    blk.extend_from_slice(b"data");
    // Must return (not spin) - and the hostile record still counts as
    // its declared type (encryption) before the walk stops.
    match parse_block_v5(&blk, 0) {
        BlockResult::File { entry, .. } => assert!(entry.encrypted),
        other => panic!(
            "expected file block, got {}",
            match other {
                BlockResult::NeedMore => "NeedMore",
                BlockResult::Corrupt(w) => w,
                BlockResult::EncryptedHeaders => "EncryptedHeaders",
                BlockResult::BadPassword => "BadPassword",
                BlockResult::V4EncryptedHeaders { .. } => "V4EncryptedHeaders",
                BlockResult::Crypt { .. } => "Crypt",
                BlockResult::End => "End",
                BlockResult::Skip { .. } => "Skip",
                BlockResult::File { .. } => unreachable!(),
            }
        ),
    }
}

/// RAR5 extra-area encryption record whose declared size is SMALLER
/// than the type vint (rec_size=0). The old guard only checked the
/// upper bound, so `&hdr[rec_start+tn .. rec_start+rec_size]` had
/// start > end and panicked. Must parse without panicking.
#[test]
fn v5_encryption_record_size_below_type_vint_no_panic() {
    fn vint_enc(mut v: u64, out: &mut Vec<u8>) {
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
    // Extra record: size vint = 0, then type vint = 0x01 (encryption).
    // rec_size (0) < tn (1) is the panic trigger.
    let mut extra = Vec::new();
    vint_enc(0, &mut extra); // rec_size = 0
    vint_enc(0x01, &mut extra); // rec_type = file encryption
    let mut hdr = Vec::new();
    vint_enc(2, &mut hdr); // type 2 = file
    vint_enc(0x03, &mut hdr); // flags: extra + data
    vint_enc(extra.len() as u64, &mut hdr); // extra size
    vint_enc(4, &mut hdr); // data size
    let mut body = Vec::new();
    vint_enc(0, &mut body); // file flags
    vint_enc(100, &mut body); // unpacked
    vint_enc(0, &mut body); // attrs
    vint_enc(0, &mut body); // comp info: store
    vint_enc(0, &mut body); // host
    vint_enc(4, &mut body); // name len
    body.extend_from_slice(b"x.mk");
    hdr.extend_from_slice(&body);
    hdr.extend_from_slice(&extra);
    let mut sized = Vec::new();
    vint_enc(hdr.len() as u64, &mut sized);
    let mut blk = Vec::new();
    let mut crc = crc32fast::Hasher::new();
    crc.update(&sized);
    crc.update(&hdr);
    blk.extend_from_slice(&crc.finalize().to_le_bytes());
    blk.extend_from_slice(&sized);
    blk.extend_from_slice(&hdr);
    blk.extend_from_slice(b"data");
    // The record is malformed, so crypt params stay None, but the flag
    // is set from the record type before the (now guarded) slice.
    match parse_block_v5(&blk, 0) {
        BlockResult::File { entry, .. } => {
            assert!(entry.encrypted);
            assert!(
                entry.crypt.is_none(),
                "malformed record must not yield crypt params"
            );
        }
        other => panic!(
            "expected file block, got {}",
            match other {
                BlockResult::NeedMore => "NeedMore",
                BlockResult::Corrupt(w) => w,
                BlockResult::EncryptedHeaders => "EncryptedHeaders",
                BlockResult::BadPassword => "BadPassword",
                BlockResult::V4EncryptedHeaders { .. } => "V4EncryptedHeaders",
                BlockResult::Crypt { .. } => "Crypt",
                BlockResult::End => "End",
                BlockResult::Skip { .. } => "Skip",
                BlockResult::File { .. } => unreachable!(),
            }
        ),
    }
}

#[test]
fn real_world_encrypted_headers_detected() {
    // Prefix of the real obfuscated release (encrypted headers):
    // signature + block crc 8eb85a8b + hsize 0x21 + type 4.
    let mut prefix = Vec::new();
    prefix.extend_from_slice(SIG5);
    prefix.extend_from_slice(&[0x8e, 0xb8, 0x5a, 0x8b, 0x21, 0x04]);
    prefix.extend_from_slice(&[0u8; 64]);
    let mut m = VolumeMapper::new(4096);
    m.feed(0, &prefix);
    // CRC of our zero-padded fake body won't match, so we accept either
    // blocker - the point is it must NOT parse as mappable store data.
    assert!(m.blocker.is_some());
    assert!(m.entries.is_empty());
}

/// A data area declared past the end of the volume must blocker the
/// mapper, not sail through as a COMPLETE volume. Without the bound
/// the cursor lands beyond `volume_size`, the next parse sees an
/// empty window, and the EOF rule declares the volume complete - the
/// mapper then vouches for bytes that were never posted.
#[test]
fn data_area_past_the_volume_end_is_corrupt() {
    let data = payload(4_000, 3);
    let vol = fixtures::rar5_volume_oversized("movie.mkv", 8 << 20, &data, 8 << 20);
    let mut m = VolumeMapper::new(vol.len() as u64);
    feed_shuffled(&mut m, &vol, 700, 5);
    assert!(
        matches!(m.blocker, Some(MapBlocker::Corrupt(_))),
        "expected a Corrupt blocker, got {:?}",
        m.blocker
    );
    assert!(
        !m.complete,
        "an overrunning volume must never read complete"
    );
    assert_eq!(m.mapped_through(), m.cursor);
}

/// The bound's OTHER term, which is the one TODO 118 item 2 is about:
/// the volume length is the POST's declaration, not a measurement, and
/// a healthy set whose declaration is a few dozen bytes short refuses
/// on EVERY volume at once.
///
/// `volume_size` is `=ybegin size=`, threaded from `yenc::Decoded`
/// through `Extractor::write*` into `slots[slot].size` and handed to the
/// mapper at classification. Nothing verifies it - `check_part_geometry`
/// declines to check `=ypart end=` against it in as many words, on the
/// grounds that real posters get the field wrong on otherwise perfectly
/// good articles - so a poster-side error in this one field lands here
/// as a hard refusal of a set that is not damaged at all.
///
/// The measured slack is tiny, which is why a whole set goes at once
/// rather than one odd volume. On RARLAB rar 7.23 store volumes (`-ma5
/// -m0 -v100k`, 23 Aug 2026) a NON-final volume tolerates 16 bytes of
/// understatement and refuses at 17; a final or single volume tolerates
/// 8 and refuses at 9. The synthetic volumes here have their own tail
/// block and so their own slack, which is why this asserts a clean map
/// at the true length and a refusal well past any of it rather than
/// pinning a byte count the fixture would own.
#[test]
fn an_understated_volume_declaration_refuses_every_volume_of_a_healthy_set() {
    let total = payload(250_000, 9);
    let vols: Vec<Vec<u8>> = vec![
        fixtures::rar5_volume_n(&[("film.mkv", 250_000, &total[..100_000], false, true)], 0),
        fixtures::rar5_volume_n(
            &[("film.mkv", 250_000, &total[100_000..200_000], true, true)],
            1,
        ),
        fixtures::rar5_volume_n(&[("film.mkv", 250_000, &total[200_000..], true, false)], 2),
    ];
    // At the length the volumes really are, every one of them maps.
    for (i, v) in vols.iter().enumerate() {
        let mut m = VolumeMapper::new(v.len() as u64);
        feed_shuffled(&mut m, v, 700, 5);
        assert!(
            m.blocker.is_none() && m.complete && m.entries.len() == 1,
            "vol {i} is healthy: {:?}",
            m.blocker
        );
    }
    // Same bytes, same order, a declaration 64 bytes short: the whole
    // set goes, and it goes with the reason the field report carried.
    for (i, v) in vols.iter().enumerate() {
        let mut m = VolumeMapper::new(v.len() as u64 - 64);
        feed_shuffled(&mut m, v, 700, 5);
        assert!(
            matches!(
                m.blocker,
                Some(MapBlocker::Corrupt("data area exceeds volume"))
            ),
            "vol {i} must refuse on the bound, got {:?}",
            m.blocker
        );
        assert!(!m.complete, "a refused volume must never read complete");
    }
}

/// And the bound is ONE-SIDED, so the opposite poster error is silent.
///
/// A declaration that OVERSTATES the volume - by one byte or by twice
/// its length - never trips anything: the parse walks the real blocks,
/// the end-of-archive block sets `complete`, and the surplus is simply
/// never visited. That asymmetry is worth pinning because it decides
/// what a field report means: "data area exceeds volume" on a whole set
/// is evidence of a declaration that is too SMALL (or of a header that
/// genuinely overruns), and can never be evidence of one too large.
/// Anything wanting to catch the too-large direction needs a different
/// check, at settle, against bytes that actually arrived.
#[test]
fn the_volume_bound_is_one_sided_so_an_overstated_declaration_is_invisible() {
    let data = payload(120_000, 4);
    let vol = fixtures::rar5_volume(&[("film.mkv", 120_000, &data, false, false)]);
    for over in [1u64, 64, 100_000, vol.len() as u64] {
        let mut m = VolumeMapper::new(vol.len() as u64 + over);
        feed_shuffled(&mut m, &vol, 700, 5);
        assert!(
            m.blocker.is_none(),
            "over by {over} must not blocker: {:?}",
            m.blocker
        );
        assert!(
            m.complete && m.entries.len() == 1,
            "over by {over} still maps the volume whole"
        );
    }
}

/// ...and a data area declared so large that the cursor arithmetic
/// WRAPS must be refused by the same bound.
///
/// `data_size` is an attacker-declared vint and `vint` reads values
/// within a few bytes of `u64::MAX`, so `base + envelope + data_size`
/// overflowed: in release it wrapped to a SMALL `next`, which is still
/// greater than `cursor` and no longer greater than `volume_size` - so
/// it slipped past both of `advance_to`'s tests and defeated the very
/// bound the test above installs. In debug (and under `cargo test`,
/// where overflow checks are on) the same line panicked outright. The
/// RAR4 twin has used `checked_add` for this since the M5 CRC gate; the
/// RAR5 half now matches. A poster stamps the header CRC over whatever
/// fields it likes, so the CRC gate is no defence here.
#[test]
fn a_v5_data_area_that_wraps_the_cursor_is_corrupt() {
    let data = payload(4_000, 3);
    // Chosen so `base + envelope + data_size` exceeds u64::MAX: the
    // plain sum wraps to a small value that passes the volume bound.
    let vol = fixtures::rar5_volume_oversized("movie.mkv", 8 << 20, &data, u64::MAX - 16);
    let mut m = VolumeMapper::new(vol.len() as u64);
    feed_shuffled(&mut m, &vol, 700, 5);
    assert!(
        matches!(m.blocker, Some(MapBlocker::Corrupt(_))),
        "expected a Corrupt blocker, got {:?}",
        m.blocker
    );
    assert!(
        !m.complete,
        "a volume whose cursor arithmetic wraps must never read complete"
    );
    // The wrapped cursor is the real damage: an entry surviving with
    // `data_off + data_len` wrapped is what `map_span_into` then
    // computes destinations from.
    assert!(
        m.entries
            .iter()
            .all(|e| e.data_off.checked_add(e.data_len).is_some()),
        "no surviving entry may carry a wrapped data area"
    );
}

/// The bound must not fire on a legitimate split set, where every
/// piece's `data_len` is the PER-VOLUME portion and lands exactly on
/// the volume end - the same invariant the EOF rule already assumes.
#[test]
fn volume_bound_leaves_real_split_sets_alone() {
    let total = payload(300_000, 4);
    let vols = [
        fixtures::rar5_volume_n(&[("f.mkv", 300_000, &total[..100_000], false, true)], 0),
        fixtures::rar5_volume_n(
            &[("f.mkv", 300_000, &total[100_000..200_000], true, true)],
            1,
        ),
        fixtures::rar5_volume_n(&[("f.mkv", 300_000, &total[200_000..], true, false)], 2),
    ];
    let mappers: Vec<VolumeMapper> = vols
        .iter()
        .map(|v| {
            let mut m = VolumeMapper::new(v.len() as u64);
            feed_shuffled(&mut m, v, 7000, 6);
            assert!(m.blocker.is_none(), "{:?}", m.blocker);
            assert!(m.complete);
            m
        })
        .collect();
    let refs: Vec<&VolumeMapper> = mappers.iter().collect();
    let am = ArchiveMap::resolve(&refs);
    assert_eq!(am.bases.get(&(0, 0)), Some(&0));
    assert_eq!(am.bases.get(&(1, 0)), Some(&100_000));
    assert_eq!(am.bases.get(&(2, 0)), Some(&200_000));
}

#[test]
fn not_rar_rejected() {
    let mut m = VolumeMapper::new(1000);
    m.feed(0, b"PK\x03\x04 definitely a zip file padding padding");
    assert_eq!(m.blocker, Some(MapBlocker::NotRar));
}

// -- encrypted RAR5, validated against REAL `rar 7.23` archives
//    (testdata/rar5/, password testpw123, payload secret.bin) --

const PW: &str = "testpw123";
const ENC_STORE: &[u8] = include_bytes!("../../testdata/rar5/enc-store.rar");
const ENC_HDRS: &[u8] = include_bytes!("../../testdata/rar5/enc-hdrs.rar");
const ENC_V1: &[u8] = include_bytes!("../../testdata/rar5/enc-vols.part1.rar");
const ENC_V2: &[u8] = include_bytes!("../../testdata/rar5/enc-vols.part2.rar");
const ENC_V3: &[u8] = include_bytes!("../../testdata/rar5/enc-vols.part3.rar");
const SECRET: &[u8] = include_bytes!("../../testdata/rar5/secret.bin");

// -- encrypted RAR4, from the vendored rars writer and validated with
//    the reference decoder (`unrar t -ptestpw123`) before committing;
//    see testdata/rar4/README.md. Same password, its own payload --

const V4_ENC_STORE: &[u8] = include_bytes!("../../testdata/rar4/enc-store.rar");
const V4_ENC_HDRS: &[u8] = include_bytes!("../../testdata/rar4/enc-hdrs.rar");
const V4_ENC_V1: &[u8] = include_bytes!("../../testdata/rar4/enc-vols.part1.rar");
const V4_ENC_V2: &[u8] = include_bytes!("../../testdata/rar4/enc-vols.part2.rar");
const V4_ENC_V3: &[u8] = include_bytes!("../../testdata/rar4/enc-vols.part3.rar");
const V4_ENC_HV1: &[u8] = include_bytes!("../../testdata/rar4/enc-hdr-vols.part1.rar");
const V4_ENC_HV2: &[u8] = include_bytes!("../../testdata/rar4/enc-hdr-vols.part2.rar");
const V4_ENC_HV3: &[u8] = include_bytes!("../../testdata/rar4/enc-hdr-vols.part3.rar");
const V4_SECRET: &[u8] = include_bytes!("../../testdata/rar4/secret.bin");

fn mapper_with(pw: Option<&str>, vol: &[u8]) -> VolumeMapper {
    let mut m = VolumeMapper::with_password(vol.len() as u64, pw.map(std::sync::Arc::from));
    m.feed(0, vol);
    m
}

#[test]
fn real_encrypted_data_archive_maps_with_password() {
    let m = mapper_with(Some(PW), ENC_STORE);
    assert_eq!(m.blocker, None, "encrypted store must stay mappable");
    assert!(m.complete);
    assert_eq!(m.entries.len(), 1);
    let e = &m.entries[0];
    assert_eq!(e.name, "secret.bin");
    assert_eq!(e.method, Method::Store);
    assert!(e.encrypted);
    assert_eq!(e.unpacked_size, SECRET.len() as u64);
    // Ciphertext data area = align16(plaintext).
    assert_eq!(e.data_len, (SECRET.len() as u64 + 15) & !15);
    let c = e
        .crypt
        .as_ref()
        .and_then(EntryCrypt::rar5)
        .expect("crypt params parsed");
    assert_eq!(c.lg2_count, 15);
    assert!(c.check.is_some(), "real rar writes a check value");
}

#[test]
fn real_encrypted_data_archive_without_password_blocks() {
    let m = mapper_with(None, ENC_STORE);
    assert_eq!(m.blocker, Some(MapBlocker::EncryptedNoPassword));
    // The entry is still recorded (needs_password relies on it).
    assert!(m.entries.iter().any(|e| e.encrypted));
}

#[test]
fn real_encrypted_data_archive_wrong_password_rejected() {
    let m = mapper_with(Some("nottherightpw"), ENC_STORE);
    assert_eq!(m.blocker, Some(MapBlocker::BadPassword));
}

#[test]
fn real_encrypted_headers_archive_parses_with_password() {
    let m = mapper_with(Some(PW), ENC_HDRS);
    assert_eq!(m.blocker, None, "headers must decrypt");
    assert!(m.complete);
    assert_eq!(m.entries.len(), 1);
    let e = &m.entries[0];
    assert_eq!(e.name, "secret.bin");
    assert!(e.encrypted && e.crypt.is_some());
    // Data must decrypt to the payload: one CBC stream from the
    // entry's IV over its data area.
    let keys = e.crypt.as_ref().unwrap().derive(PW).unwrap();
    let mut data = ENC_HDRS[e.data_off as usize..(e.data_off + e.data_len) as usize].to_vec();
    crate::rarcrypt::cbc_decrypt(&keys.aes, &keys.iv, &mut data);
    assert_eq!(&data[..SECRET.len()], SECRET);
}

#[test]
fn real_encrypted_headers_wrong_or_missing_password() {
    let m = mapper_with(None, ENC_HDRS);
    assert_eq!(m.blocker, Some(MapBlocker::EncryptedHeaders));
    assert!(m.entries.is_empty());
    let m = mapper_with(Some("nope"), ENC_HDRS);
    assert_eq!(m.blocker, Some(MapBlocker::BadPassword));
}

/// Multi-volume: the crypt record (salt AND iv) repeats verbatim in
/// every volume - one continuous CBC stream, arbitrary split points,
/// total ciphertext = align16(unpacked). Everything the extractor's
/// decrypt-at-finish design rests on, proven against real output.
#[test]
fn real_encrypted_volumes_are_one_cbc_stream() {
    let vols = [ENC_V1, ENC_V2, ENC_V3];
    let mut mappers = Vec::new();
    for v in vols {
        let m = mapper_with(Some(PW), v);
        assert_eq!(m.blocker, None);
        assert_eq!(m.entries.len(), 1);
        mappers.push(m);
    }
    let c0 = mappers[0].entries[0].crypt.clone().unwrap();
    let r0 = c0.rar5().unwrap();
    let mut cipher = Vec::new();
    for m in &mappers {
        let e = &m.entries[0];
        // The KEY MATERIAL repeats verbatim - that is what makes the
        // volumes one stream. The tweaked-checksum flag does NOT: real
        // rar sets it only on the piece that carries a checksum, so
        // comparing whole records here would false-fail.
        let c = e.crypt.as_ref().and_then(EntryCrypt::rar5).unwrap();
        assert_eq!((c.salt, c.iv), (r0.salt, r0.iv), "params repeat per volume");
        cipher.push((e.data_off, e.data_len));
    }
    // Split flags chain head → middle → tail.
    assert!(!mappers[0].entries[0].split_before && mappers[0].entries[0].split_after);
    assert!(mappers[1].entries[0].split_before && mappers[1].entries[0].split_after);
    assert!(mappers[2].entries[0].split_before && !mappers[2].entries[0].split_after);
    let mut stream = Vec::new();
    for (i, (off, len)) in cipher.iter().enumerate() {
        stream.extend_from_slice(&vols[i][*off as usize..(*off + *len) as usize]);
    }
    assert_eq!(stream.len() as u64, (SECRET.len() as u64 + 15) & !15);
    let keys = c0.derive(PW).unwrap();
    crate::rarcrypt::cbc_decrypt(&keys.aes, &keys.iv, &mut stream);
    assert_eq!(
        &stream[..SECRET.len()],
        SECRET,
        "reassembled stream decrypts"
    );
}

// -- the same ladder for RAR4, against unrar-validated archives --

/// `rar -m0 -p` RAR4: plaintext headers, AES-128 data. The entry must
/// stay MAPPABLE (store-shaped, so the one-pass path owns it) and
/// carry the salt the key schedule needs.
#[test]
fn real_v4_encrypted_data_archive_maps_with_password() {
    let m = mapper_with(Some(PW), V4_ENC_STORE);
    assert_eq!(m.blocker, None, "RAR4 encrypted store must stay mappable");
    assert!(m.complete);
    assert_eq!(m.entries.len(), 1);
    let e = &m.entries[0];
    assert_eq!(e.name, "inner.bin");
    assert_eq!(e.method, Method::Store);
    assert!(e.encrypted);
    assert_eq!(e.unpacked_size, V4_SECRET.len() as u64);
    // Ciphertext data area = align16(plaintext), same as RAR5.
    assert_eq!(e.data_len, (V4_SECRET.len() as u64 + 15) & !15);
    assert!(
        matches!(e.crypt, Some(EntryCrypt::Rar4(Rar4Crypt { salt: Some(_) }))),
        "RAR4 crypt params with the header salt, got {:?}",
        e.crypt
    );
    // The stored CRC is the PLAINTEXT's - the only thing that can
    // adjudicate the password once the finish pass has decrypted.
    assert_eq!(e.file_crc, Some(crc32fast::hash(V4_SECRET)));
    // …and the data really is one CBC stream from the derived IV.
    let keys = e.crypt.as_ref().unwrap().derive(PW).unwrap();
    let mut data = V4_ENC_STORE[e.data_off as usize..(e.data_off + e.data_len) as usize].to_vec();
    crate::rarcrypt::cbc_decrypt(&keys.aes, &keys.iv, &mut data);
    assert_eq!(&data[..V4_SECRET.len()], V4_SECRET);
}

/// No password: the same "keep the volumes, prompt for a key" verdict
/// RAR5 gets, NOT the unrar-fallback NotStore this used to give.
#[test]
fn real_v4_encrypted_data_archive_without_password_blocks() {
    let m = mapper_with(None, V4_ENC_STORE);
    assert_eq!(m.blocker, Some(MapBlocker::EncryptedNoPassword));
    assert!(m.entries.iter().any(|e| e.encrypted));
}

/// RAR4 stores no password check, so a wrong password CANNOT be
/// rejected here - the entry maps and the finish pass adjudicates it
/// against the plaintext CRC. Mapping it is what keeps the assembled
/// bytes identical to the posted volumes, so the demote costs nothing.
#[test]
fn real_v4_wrong_password_is_not_detectable_before_decrypting() {
    let m = mapper_with(Some("nottherightpw"), V4_ENC_STORE);
    assert_eq!(m.blocker, None);
    let e = &m.entries[0];
    let keys = e.crypt.as_ref().unwrap().derive("nottherightpw").unwrap();
    assert!(
        !e.crypt.as_ref().unwrap().check_verifies(&keys),
        "nothing in RAR4 may report a password as verified"
    );
    // Which is exactly why the CRC gate has to exist: the wrong key
    // produces plausible-looking bytes with a CRC that misses.
    let mut data = V4_ENC_STORE[e.data_off as usize..(e.data_off + e.data_len) as usize].to_vec();
    crate::rarcrypt::cbc_decrypt(&keys.aes, &keys.iv, &mut data);
    assert_ne!(
        crc32fast::hash(&data[..V4_SECRET.len()]),
        e.file_crc.unwrap()
    );
}

/// `rar -m0 -hp` RAR4: every block past the plaintext main header is
/// `8-byte salt + AES-128-CBC`, and the file DATA carries its own salt
/// under the same password.
#[test]
fn real_v4_encrypted_headers_archive_parses_with_password() {
    let m = mapper_with(Some(PW), V4_ENC_HDRS);
    assert_eq!(m.blocker, None, "RAR4 headers must decrypt");
    assert!(m.complete);
    assert_eq!(m.entries.len(), 1);
    let e = &m.entries[0];
    assert_eq!(e.name, "inner.bin");
    assert!(e.encrypted && e.crypt.is_some());
    assert_eq!(e.method, Method::Store);
    let keys = e.crypt.as_ref().unwrap().derive(PW).unwrap();
    let mut data = V4_ENC_HDRS[e.data_off as usize..(e.data_off + e.data_len) as usize].to_vec();
    crate::rarcrypt::cbc_decrypt(&keys.aes, &keys.iv, &mut data);
    assert_eq!(&data[..V4_SECRET.len()], V4_SECRET);
}

/// Unlike `-p`, a RAR4 `-hp` set DOES catch a wrong password: the
/// decrypted header's CRC16 misses. No password at all stays opaque.
#[test]
fn real_v4_encrypted_headers_wrong_or_missing_password() {
    let m = mapper_with(None, V4_ENC_HDRS);
    assert_eq!(m.blocker, Some(MapBlocker::EncryptedHeaders));
    assert!(m.entries.is_empty());
    let m = mapper_with(Some("nope"), V4_ENC_HDRS);
    assert_eq!(m.blocker, Some(MapBlocker::BadPassword));
    assert!(m.entries.is_empty(), "no garbage entry may survive");
}

/// The multi-volume fact the whole one-pass design rests on, for RAR4:
/// the salt repeats verbatim in every volume, the pieces concatenate
/// into ONE AES-128-CBC stream of align16(unpacked) bytes, and the
/// WHOLE-FILE plaintext CRC rides the LAST piece only.
#[test]
fn real_v4_encrypted_volumes_are_one_cbc_stream() {
    for vols in [
        [V4_ENC_V1, V4_ENC_V2, V4_ENC_V3],
        [V4_ENC_HV1, V4_ENC_HV2, V4_ENC_HV3],
    ] {
        let mappers: Vec<VolumeMapper> = vols
            .iter()
            .map(|v| {
                let m = mapper_with(Some(PW), v);
                assert_eq!(m.blocker, None);
                assert_eq!(m.entries.len(), 1);
                m
            })
            .collect();
        let c0 = mappers[0].entries[0].crypt.clone().unwrap();
        let mut cipher = Vec::new();
        for m in &mappers {
            let e = &m.entries[0];
            assert_eq!(e.crypt.as_ref(), Some(&c0), "one salt for the whole set");
            assert_eq!(e.unpacked_size, V4_SECRET.len() as u64);
            cipher.push((e.data_off, e.data_len));
        }
        assert!(!mappers[0].entries[0].split_before && mappers[0].entries[0].split_after);
        assert!(mappers[1].entries[0].split_before && mappers[1].entries[0].split_after);
        assert!(mappers[2].entries[0].split_before && !mappers[2].entries[0].split_after);
        // Only the tail's CRC describes the plaintext; the earlier
        // pieces' fields cover their own volume's packed bytes, which
        // is why the finish pass reads the tail's and not the head's.
        assert_eq!(
            mappers[2].entries[0].file_crc,
            Some(crc32fast::hash(V4_SECRET))
        );
        assert_ne!(
            mappers[0].entries[0].file_crc,
            Some(crc32fast::hash(V4_SECRET))
        );
        let mut stream = Vec::new();
        for (i, (off, len)) in cipher.iter().enumerate() {
            stream.extend_from_slice(&vols[i][*off as usize..(*off + *len) as usize]);
        }
        assert_eq!(stream.len() as u64, (V4_SECRET.len() as u64 + 15) & !15);
        let keys = c0.derive(PW).unwrap();
        crate::rarcrypt::cbc_decrypt(&keys.aes, &keys.iv, &mut stream);
        assert_eq!(
            &stream[..V4_SECRET.len()],
            V4_SECRET,
            "reassembled stream decrypts"
        );
    }
}

/// Pre-3.0 RAR ciphers have no key schedule here, so those entries
/// must keep routing to unrar rather than mapping with no `crypt`.
#[test]
fn v4_pre_30_encryption_still_falls_back() {
    let mut vol = V4_ENC_STORE.to_vec();
    // unp_ver lives at header start + 25 (7 sig + 20-byte prologue is
    // the main header; the file header starts at 20).
    let unp_ver = 20 + 24;
    assert_eq!(vol[unp_ver], 29, "fixture layout moved");
    vol[unp_ver] = 20; // RAR 2.0
    restamp_v4_block(&mut vol, V4_FIRST_BLOCK);
    let m = mapper_with(Some(PW), &vol);
    assert_eq!(m.blocker, Some(MapBlocker::NotStore));
    let e = &m.entries[0];
    assert!(e.encrypted && e.crypt.is_none());
    assert!(
        e.file_crc.is_none(),
        "an undecryptable entry vouches for nothing"
    );
}

/// The RAR4 encrypted fixture writer must produce what the real
/// archives above do: mappable store entries, one CBC stream across
/// the split, the plaintext CRC on the tail, and `-hp` headers this
/// parser reads with the password and rejects without it. The e2e
/// suite posts these, so a drift here would test a shape no archiver
/// emits.
#[test]
fn fixture_writer_v4_encrypted_matches_parser() {
    let plain = payload(40_001, 11);
    let f = fixtures::encrypt_file_v4("pw4!", &plain, 21);
    assert_eq!(f.cipher.len() as u64, (plain.len() as u64 + 15) & !15);
    let (a, n) = (17_003, f.cipher.len());
    let split: [(&str, _, std::ops::Range<usize>, bool, bool); 2] = [
        ("a.bin", &f, 0..a, false, true),
        ("a.bin", &f, a..n, true, false),
    ];
    for headers_encrypted in [false, true] {
        let vols: Vec<Vec<u8>> = split
            .iter()
            .map(|p| {
                let one = [p.clone()];
                if headers_encrypted {
                    fixtures::rar4_volume_enc_headers(&one, "pw4!", 3)
                } else {
                    fixtures::rar4_volume_enc(&one)
                }
            })
            .collect();
        let mut stream = Vec::new();
        let mut crypt = None;
        for (i, v) in vols.iter().enumerate() {
            let m = mapper_with(Some("pw4!"), v);
            assert_eq!(m.blocker, None, "hp={headers_encrypted} vol={i}");
            assert!(m.complete);
            let e = &m.entries[0];
            assert_eq!(e.method, Method::Store);
            assert!(e.encrypted);
            assert_eq!(e.unpacked_size, plain.len() as u64);
            assert_eq!(e.split_before, i == 1);
            assert_eq!(e.split_after, i == 0);
            let c = e.crypt.clone().unwrap();
            assert_eq!(crypt.get_or_insert(c.clone()), &c, "one salt per set");
            stream.extend_from_slice(&v[e.data_off as usize..(e.data_off + e.data_len) as usize]);
            // Only the tail vouches for the plaintext.
            assert_eq!(e.file_crc == Some(f.crc), i == 1);
        }
        let keys = crypt.unwrap().derive("pw4!").unwrap();
        crate::rarcrypt::cbc_decrypt(&keys.aes, &keys.iv, &mut stream);
        assert_eq!(&stream[..plain.len()], &plain[..]);
        if headers_encrypted {
            assert_eq!(
                mapper_with(None, &vols[0]).blocker,
                Some(MapBlocker::EncryptedHeaders)
            );
            assert_eq!(
                mapper_with(Some("wrong"), &vols[0]).blocker,
                Some(MapBlocker::BadPassword)
            );
        }
    }
}

/// Our encrypted fixture writer must round-trip through the parser
/// exactly like real rar output does (the e2e suite leans on it).
#[test]
fn fixture_writer_encrypted_matches_parser() {
    let plain = payload(50_001, 3);
    let f = fixtures::encrypt_file("pw!", &plain, 9);
    assert_eq!(f.cipher.len() as u64, (plain.len() as u64 + 15) & !15);
    let vol = fixtures::rar5_volume_enc(&[("a.bin", &f, 0..f.cipher.len(), false, false)], None);
    let m = mapper_with(Some("pw!"), &vol);
    assert_eq!(m.blocker, None);
    let e = &m.entries[0];
    assert_eq!(
        e.crypt.as_ref().and_then(EntryCrypt::rar5).unwrap().salt,
        f.salt
    );
    // And header-encrypted wrapping parses too.
    let hv = fixtures::rar5_volume_enc_headers(
        &[("a.bin", &f, 0..f.cipher.len(), false, false)],
        None,
        "pw!",
        7,
    );
    let m = mapper_with(Some("pw!"), &hv);
    assert_eq!(m.blocker, None, "encrypted headers from fixture writer");
    assert_eq!(m.entries.len(), 1);
    assert!(m.complete);
    let m = mapper_with(Some("wrong"), &hv);
    assert_eq!(m.blocker, Some(MapBlocker::BadPassword));
}

/// The no-password check-value probe: harvest crypt params off an
/// on-disk archive and rule a candidate in or out without decrypting.
/// Volume 0's main header carries no volume-number field, so the SAME
/// pieces produce a file exactly one byte shorter at `vol_no` 0 than at
/// 1. Pinned here, where the asymmetry originates, because every
/// multi-volume fixture in the workspace has to compensate for it and
/// each one was re-deriving it by hand - or, more often, not.
///
/// A store set is "uniform" when the volume FILES are the same size, so
/// a fixture that splits its payload into equal pieces is NOT uniform:
/// volume 0 comes out a byte short. That matters because the extractor's
/// arithmetic gate speculates bases under a uniform premise and demotes
/// the group when headers contradict it - which made
/// `nested_inner_par2_repairs_data_damaged_store_layer` a race between
/// two correct demotion reasons, passing under load and failing on a
/// slower runner (it reproduced 8 times in 30 on macOS). A fixture that
/// wants a uniform set gives volume 0 one byte MORE data; one that wants
/// a non-uniform set can keep equal pieces, which is a legitimate shape
/// real posters produce.
///
/// If this test fails, the helper's header layout moved and every
/// multi-volume fixture's geometry needs re-checking.
#[test]
fn volume_zero_header_is_one_byte_shorter_than_the_rest() {
    let body = vec![b'x'; 4096];
    let piece = |crc: Option<u32>| vec![("v.bin", 8192u64, &body[..], false, true, crc)];
    let v0 = fixtures::rar5_volume_n_crc(&piece(Some(1)), 0);
    let v1 = fixtures::rar5_volume_n_crc(&piece(Some(1)), 1);
    assert_eq!(
        v1.len(),
        v0.len() + 1,
        "vol 0 must be exactly one byte shorter for the same pieces \
         (got {} at vol 0, {} at vol 1) - every multi-volume fixture's \
         uniformity depends on this",
        v0.len(),
        v1.len()
    );
    // ...so equal pieces are NOT a uniform set, and one extra byte in
    // volume 0 IS - the two facts fixtures actually need.
    let mut long = body.clone();
    long.push(b'x');
    let v0_plus =
        fixtures::rar5_volume_n_crc(&[("v.bin", 8192, &long[..], false, true, Some(1))], 0);
    assert_eq!(
        v0_plus.len(),
        v1.len(),
        "one extra data byte in vol 0 evens the files up"
    );
}

#[test]
fn crypt_probe_verifies_without_decrypt() {
    let dir = std::env::temp_dir().join(format!("nzbkit-cryptprobe-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let write = |name: &str, bytes: &[u8]| {
        let p = dir.join(name);
        std::fs::write(&p, bytes).unwrap();
        p
    };

    // Data-encrypted set: probe reads the first entry's crypt record.
    let f = fixtures::encrypt_file("open-sesame", b"secret payload bytes", 9);
    let vol = fixtures::rar5_volume_enc(&[("s.bin", &f, 0..f.cipher.len(), false, false)], None);
    let probe = crypt_probe(&write("data.rar", &vol)).expect("encrypted set yields a probe");
    assert_eq!(probe.verify("open-sesame"), PwVerdict::Verified);
    assert_eq!(probe.verify("wrong-one"), PwVerdict::Rejected);

    // Header-encrypted set: probe reads the type-4 block before it
    // blocks (no password given to the probe).
    let hv = fixtures::rar5_volume_enc_headers(
        &[("s.bin", &f, 0..f.cipher.len(), false, false)],
        None,
        "hp-secret",
        7,
    );
    let hprobe = crypt_probe(&write("hdr.rar", &hv)).expect("header-crypt yields a probe");
    assert_eq!(hprobe.verify("hp-secret"), PwVerdict::Verified);
    assert_eq!(hprobe.verify("nope"), PwVerdict::Rejected);

    // Check-less set: no stored check to veto with -> Indeterminate,
    // and the auto-unlock path leaves it to a real extraction attempt.
    let mut g = fixtures::encrypt_file("k", b"data here", 4);
    g.no_check = true;
    let g2 = fixtures::rar5_volume_enc(&[("x", &g, 0..g.cipher.len(), false, false)], None);
    let cl = crypt_probe(&write("nocheck.rar", &g2)).expect("still a probe");
    assert_eq!(cl.check, None);
    assert_eq!(cl.verify("k"), PwVerdict::Indeterminate);

    // A plaintext store archive is not probeable at all.
    let plain = fixtures::rar5_volume_n(&[("a.bin", 4, b"data", false, false)], 0);
    assert!(crypt_probe(&write("plain.rar", &plain)).is_none());

    let _ = std::fs::remove_dir_all(&dir);
}

/// A legacy-comment header declaring less than the 13 bytes its CRC
/// covers must be rejected, not checksummed past its own end.
///
/// The fixed-13 arms of `v4_header_crc` trusted the type and flags
/// without asking whether `head_size` could contain 13 bytes. The
/// buffer only has to be `head_size` long to reach them, so a 0x73
/// header declaring 8 indexed `h[2..13]` on a 10-byte slice and
/// panicked. Found by `rar_name_probe` fuzzing (13 Aug) on the
/// truncated-prefix shape, where a probe holds half an article; these
/// bytes are the reduced crash input, one usenet article of an
/// attacker's choosing.
#[test]
fn legacy_comment_header_shorter_than_its_crc_range_is_rejected() {
    // "Rar!\x1a\x07\x00", then crc, type 0x73 (main), flags with
    // MHD_COMMENT, head_size = 8.
    let article: [u8; 34] = [
        82, 97, 114, 33, 26, 7, 0, 241, 251, 115, 26, 110, 8, 0, 0, 0, 0, 0, 0, 0, 0, 82, 97, 0, 0,
        0, 0, 176, 74, 74, 255, 255, 255, 212,
    ];
    // Past the signature, and cut where the probe's short-article
    // shape cuts: 10 bytes, three short of the range it would cover.
    let head = &article[7..17];
    assert_eq!(rd_u16(&head[5..]) as usize, 8, "head_size 8 is the point");
    assert!(
        matches!(v4_header_crc(head), V4HeaderCrc::Mismatch),
        "a block too small for its own CRC range is not authoritative"
    );

    // Same header with the whole article behind it: no panic to have,
    // and the answer must still be Mismatch rather than a CRC taken
    // over the bytes of whatever block follows.
    assert!(matches!(
        v4_header_crc(&article[7..]),
        V4HeaderCrc::Mismatch
    ));

    // And through the parser the fuzz target actually calls.
    for cut in [article.len(), article.len() / 2] {
        let _ = crate::nameprobe::rar_head(&article[..cut], cut as u64);
    }
}

/// The other three coverage arms of `v4_header_crc`, each fed a header
/// too short for the range its type implies. The test above pins 0x73,
/// the arm the fuzzer happened to reduce to; the same class lives in
/// every arm that names a fixed end, and an arm nobody exercises is
/// where the next unclamped slice gets written.
///
/// What each case pins is the arm's VERDICT, not merely the absence of
/// a panic: the `end > h.len()` belt below the match already turns an
/// unclamped arm into a Mismatch, so "it did not crash" would pass
/// against an arm with its own guard deleted. The stamped-CRC inputs
/// below are what separate rejecting the header from silently
/// checksumming a shorter range and calling it Ok.
///
/// The last case is the point of the other two: 0x77 / `UO_HEAD` is the
/// ONE shape whose coverage legitimately outruns `head_size`, into
/// owner and group names the caller has not been asked to buffer yet.
/// It must keep answering `NeedMore` - those bytes really do arrive on
/// the next feed - so a later tightening cannot fold it into the
/// `Mismatch` belt by analogy and reject archives `rar` and `unrar`
/// read.
#[test]
fn every_v4_crc_coverage_arm_survives_a_header_too_short_for_it() {
    /// A bare RAR4 block: crc, type, flags, `head_size`, zero fill.
    fn block(btype: u8, flags: u16, hsize: u16, len: usize) -> Vec<u8> {
        let mut h = vec![0u8; len.max(7)];
        h[2] = btype;
        h[3..5].copy_from_slice(&flags.to_le_bytes());
        h[5..7].copy_from_slice(&hsize.to_le_bytes());
        h
    }
    /// Stamp the CRC16 over `h[2..end]`, so a case can assert `Ok` and
    /// not merely "did not panic".
    fn stamp(h: &mut [u8], end: usize) {
        let hc = (crc32fast::hash(&h[2..end]) & 0xffff) as u16;
        h[..2].copy_from_slice(&hc.to_le_bytes());
    }

    // 0x75, the standalone comment block: the same fixed 13, reached
    // on ANY flags, so it needs no crafted flag word to get here.
    //
    // Every short case is asserted with the CRC over `h[2..head_size]`
    // ALREADY STAMPED, which is what makes the case discriminating:
    // rejecting the header answers Mismatch, while merely clamping the
    // covered range down to `head_size` would answer Ok and hand the
    // mapper a "comment block" seven bytes long. Unstamped, both
    // readings answer Mismatch and the case pins nothing.
    for hsize in [7u16, 8, 12] {
        let mut h = block(0x75, 0, hsize, hsize as usize);
        stamp(&mut h, hsize as usize);
        assert!(
            matches!(v4_header_crc(&h), V4HeaderCrc::Mismatch),
            "0x75 head_size {hsize}: too small for its own CRC range"
        );
    }
    // At exactly 13 the arm is satisfied and the CRC decides again.
    let mut h = block(0x75, 0, 13, 13);
    assert!(matches!(v4_header_crc(&h), V4HeaderCrc::Mismatch));
    stamp(&mut h, 13);
    assert!(matches!(v4_header_crc(&h), V4HeaderCrc::Ok));

    // 0x74 / 0x7a with FHD_COMMENT read `name_size` at +26, so a header
    // declaring under 32 cannot carry the field the arm needs. Terminal,
    // not `NeedMore`: `head_size` is the header's own declared length
    // and is already fully in hand, so no later byte can grow it, and
    // asking for more would wedge the mapper on a block that can never
    // be satisfied.
    for btype in [0x74u8, 0x7a] {
        for hsize in [7u16, 20, 31] {
            let mut h = block(btype, 0x0008, hsize, hsize as usize);
            stamp(&mut h, hsize as usize);
            assert!(
                matches!(v4_header_crc(&h), V4HeaderCrc::Mismatch),
                "{btype:#x} head_size {hsize}"
            );
        }
    }

    // 0x77 / UO_HEAD: 4 + 4 bytes of names past an 18-byte header.
    let mut h = block(0x77, 0x8000, 18, 18);
    h[11..13].copy_from_slice(&0x0101u16.to_le_bytes()); // sub type
    h[14..16].copy_from_slice(&4u16.to_le_bytes()); // owner name size
    h[16..18].copy_from_slice(&4u16.to_le_bytes()); // group name size
    assert!(
        matches!(v4_header_crc(&h), V4HeaderCrc::NeedMore),
        "the one arm whose coverage legitimately outruns the buffer"
    );
    // With the names fed, the coverage is satisfied and the CRC
    // adjudicates over head_size + 8, not over head_size.
    h.extend_from_slice(b"rootroot");
    assert!(matches!(v4_header_crc(&h), V4HeaderCrc::Mismatch));
    stamp(&mut h, 26);
    assert!(matches!(v4_header_crc(&h), V4HeaderCrc::Ok));
}

/// TODO 94 C: a mapper built at a stub's length parses the archive
/// behind it in FILE coordinates - entries, `map_span`, the cursor all
/// carry the base - for both dialects, and a mapper built at 0 over the
/// same bytes says NotRar, which is the disk path's old verdict and the
/// reason the stub offset has to be found BEFORE the mapper is built.
#[test]
fn a_mapper_built_at_the_stub_length_maps_the_archive_behind_it() {
    let data = payload(4_096, 3);
    let mut stub = b"MZ".to_vec();
    stub.extend(payload(1_500, 7));
    for vol in [
        fixtures::rar5_volume(&[("a.bin", 0, &data, false, false)]),
        fixtures::rar4_volume(&[("a.bin", 0, &data, false, false)]),
    ] {
        let mut file = stub.clone();
        file.extend_from_slice(&vol);
        let base = stub.len() as u64;
        let data_off = base
            + vol
                .windows(data.len())
                .position(|w| w == &data[..])
                .unwrap() as u64;

        let mut m = VolumeMapper::with_password_at(file.len() as u64, None, base);
        assert_eq!(m.archive_base(), base);
        // Fed in article-sized spans, out of order, like the stream.
        let spans: Vec<(u64, &[u8])> = file
            .chunks(700)
            .enumerate()
            .map(|(i, c)| ((i * 700) as u64, c))
            .collect();
        for (off, c) in spans.iter().rev() {
            m.feed(*off, c);
        }
        assert!(m.complete, "the volume parses to its end");
        assert!(m.blocker.is_none(), "{:?}", m.blocker);
        assert_eq!(m.entries.len(), 1);
        assert_eq!(
            m.entries[0].data_off, data_off,
            "entry offsets are file offsets"
        );
        // A span straddling the data start maps only its data part
        // (entry, inner offset, offset WITHIN the span, length).
        let mapped = m.map_span(data_off - 10, 30);
        assert_eq!(mapped, vec![(0, 0, 10, 20)]);
        // The stub itself is below mapped_through and maps to nothing:
        // exactly what the header stash keeps for a demote.
        assert!(m.map_span(0, base).is_empty());

        let mut bare = VolumeMapper::new(file.len() as u64);
        bare.feed(0, &file);
        assert!(matches!(bare.blocker, Some(MapBlocker::NotRar)));
    }
}
