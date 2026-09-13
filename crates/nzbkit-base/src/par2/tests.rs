mod name_tests;

use super::*;
// The internals `use super::*` picked up while they lived in
// par2.rs, now reached by name (TODO 106). They stay `pub(super)`
// rather than public because nothing outside `par2` has ever named
// them: `scan_packets_counted` exists so the hostile-input test can
// assert on BYTES HASHED rather than on elapsed time, and
// `scan_packets_serial` so the parallel walk can be differentially
// tested against the path it falls back to.
use super::packet::{PAR_SCAN_MIN, scan_packets_counted, scan_packets_serial};
use super::verify::VERIFY_CHUNK;

// What a set is taken to say when its packets disagree - one
// subject, its own file under the size gate (TODO 106). A CHILD of
// this module so it reaches the packet builders below through `use
// super::*` rather than copying them, which is also why it resolves
// to `par2/tests/trust_tests.rs`: `mod tests` roots its children
// under its own name - inline, as it was written, or as its own file,
// as it is now - and a `#[path]` fighting that would only hide where
// the file is.
mod trust_tests;

/// A crafted `.par2` of overlapping magics with EOF-reaching lengths used
/// to make `scan_packets` quadratic: every 16-byte cell paid an MD5 over
/// the rest of the file and then advanced ONE byte. `.par2` files come off
/// the wire and are read whole with no size cap, so this was an hours-long
/// CPU burn (an effective hang) from one downloaded file. The hash budget
/// bounds it; the scan must find no packets and digest a linear number of
/// bytes doing so.
///
/// Asserted on bytes hashed, never on elapsed time: hashed bytes are
/// exactly what the budget controls and are identical on every machine,
/// whereas a wall-clock bound says nothing on a box where this process
/// holds a fraction of a core - a 5s bound here failed reproducibly on a
/// fully loaded machine while the budget was working perfectly.
#[test]
fn hostile_overlapping_magics_do_not_hash_quadratically() {
    const N: usize = 4 << 20; // 4 MiB: ~275 GB of MD5 before the fix
    let mut input = vec![0u8; N];
    let mut start = 0usize;
    while start + 16 <= N {
        input[start..start + 8].copy_from_slice(MAGIC);
        // Length reaching to EOF, >= HEADER_LEN and 4-aligned, so it passes
        // the structural gate; the stored-MD5 field is the next cell's
        // bytes, so verification always fails and the scan resumes at +1.
        let len = ((N - start) & !3) as u64;
        input[start + 8..start + 16].copy_from_slice(&len.to_le_bytes());
        start += 16;
    }
    let mut seen = 0usize;
    let hashed = scan_packets_counted(&input, |_| seen += 1);
    assert_eq!(seen, 0, "no cell has a valid MD5, so none may be yielded");
    // The optimistic parallel walk hashes each span once and its spans
    // never overlap, so it digests at most N; the serial scan it falls
    // back to stops the moment its budget (4N, here also the 16 MiB
    // floor) would be exceeded. 5N is therefore the true ceiling and 6N
    // is a margin - against ~65536N had the budget been removed.
    assert!(
        hashed <= 6 * N as u64,
        "scan_packets hashed {hashed} bytes over a {N}-byte input \
             - the hash budget is not bounding it"
    );
    // Guard the guard: a bound nothing reaches would pass even if the
    // scan silently stopped doing any work at all.
    assert!(
        hashed >= N as u64,
        "the hostile input must actually be scanned"
    );
}

/// The parallel scan (buffers ≥ PAR_SCAN_MIN) must agree with the
/// serial scan packet-for-packet, in order - on a clean buffer, on one
/// with inter-packet garbage, and on one with a corrupt packet (which
/// makes the parallel walk abandon and fall back). A divergence here
/// is silent data corruption in repair, so compare full packet
/// identity, not just counts.
#[test]
fn parallel_scan_matches_serial_scan() {
    let set_id = [3u8; 16];
    let body = |i: u32| {
        // Recovery-slice-shaped: exponent + ~256 KiB payload, so a
        // handful of packets crosses the parallel threshold.
        let mut b = i.to_le_bytes().to_vec();
        b.extend((0..256 << 10).map(|j| (i as usize * 31 + j) as u8));
        b
    };
    for corrupt_one in [false, true] {
        let mut buf = Vec::new();
        for i in 0..24u32 {
            if i == 7 {
                buf.extend_from_slice(b"garbage between packets");
            }
            buf.extend(pkt(set_id, TYPE_RECVSLIC, &body(i)));
        }
        assert!(
            buf.len() >= PAR_SCAN_MIN,
            "fixture must take the parallel path"
        );
        if corrupt_one {
            let mid = buf.len() / 2;
            buf[mid] ^= 0xFF;
        }
        let mut serial: Vec<([u8; 16], usize, usize)> = Vec::new();
        scan_packets_serial(&buf, |p| serial.push((p.md5, p.body_offset, p.body.len())));
        let mut both: Vec<([u8; 16], usize, usize)> = Vec::new();
        scan_packets(&buf, |p| both.push((p.md5, p.body_offset, p.body.len())));
        assert_eq!(both, serial, "corrupt_one={corrupt_one}");
        assert_eq!(both.len(), if corrupt_one { 23 } else { 24 });
    }
}

/// Build a Main-packet body: block_size ‖ nfiles ‖ nfiles×16 id bytes.
fn main_body(block_size: u64, nfiles: u32) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&block_size.to_le_bytes());
    b.extend_from_slice(&nfiles.to_le_bytes());
    b.extend(std::iter::repeat_n(0u8, nfiles as usize * 16));
    b
}

/// Wrap a body in a valid packet header (magic, length, body MD5).
fn pkt(set_id: [u8; 16], ptype: &[u8; 16], body: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(MAGIC);
    p.extend_from_slice(&(HEADER_LEN + body.len() as u64).to_le_bytes());
    p.extend_from_slice(&[0u8; 16]); // md5 patched below
    p.extend_from_slice(&set_id);
    p.extend_from_slice(ptype);
    p.extend_from_slice(body);
    let md5: [u8; 16] = Md5::digest(&p[32..]).into();
    p[16..32].copy_from_slice(&md5);
    p
}

/// A Main-packet body naming REAL file ids, where `main_body`
/// above names `nfiles` zero ids - these tests need the ids to match
/// the FileDesc packets beside them.
fn main_ids(block_size: u64, ids: &[[u8; 16]]) -> Vec<u8> {
    let mut b = block_size.to_le_bytes().to_vec();
    b.extend_from_slice(&(ids.len() as u32).to_le_bytes());
    for id in ids {
        b.extend_from_slice(id);
    }
    b
}

/// Body of a FileDesc packet, name null-padded to a multiple of 4.
fn desc_body(fid: [u8; 16], md5: u8, length: u64, name: &str) -> Vec<u8> {
    let mut b = fid.to_vec();
    b.extend_from_slice(&[md5; 16]);
    b.extend_from_slice(&[md5; 16]);
    b.extend_from_slice(&length.to_le_bytes());
    b.extend_from_slice(name.as_bytes());
    while !b.len().is_multiple_of(4) {
        b.push(0);
    }
    b
}

/// [`main_ids`] with a NON-recovery id list after the recovery one
/// (M4-21) - the "verify but do not repair" half of a Main packet,
/// which `main_ids` cannot express because it derives `nfiles` from
/// the single list it is given.
fn main_ids_nonrec(block_size: u64, rec: &[[u8; 16]], non: &[[u8; 16]]) -> Vec<u8> {
    let mut b = main_ids(block_size, rec);
    for id in non {
        b.extend_from_slice(id);
    }
    b
}

/// [`desc_body`] over REAL bytes rather than a fill byte: the
/// verify-only naming tier finalizes on the whole-file MD5, so the
/// one test that follows a descriptor out to that tier needs a
/// descriptor whose digests are the payload's own.
fn desc_body_over(fid: [u8; 16], name: &str, data: &[u8]) -> Vec<u8> {
    let mut b = fid.to_vec();
    let whole: [u8; 16] = Md5::digest(data).into();
    b.extend_from_slice(&whole);
    let h16: [u8; 16] = Md5::digest(&data[..data.len().min(HASH16K_LEN)]).into();
    b.extend_from_slice(&h16);
    b.extend_from_slice(&(data.len() as u64).to_le_bytes());
    b.extend_from_slice(name.as_bytes());
    while !b.len().is_multiple_of(4) {
        b.push(0);
    }
    b
}

/// Body of a RecvSlic packet: exponent then the slice data.
fn slice_body(exp: u32, fill: u8) -> Vec<u8> {
    let mut b = exp.to_le_bytes().to_vec();
    b.extend_from_slice(&[fill; 64]);
    b
}

/// The identity a parse settled on, as a comparable string - what a
/// differential over input order compares.
fn identity(r: &Result<Par2Set, Par2Error>) -> String {
    match r {
        Err(e) => format!("Err({e:?})"),
        Ok(s) => format!(
            "bs={} files={:?}",
            s.block_size,
            s.files
                .iter()
                .map(|f| (f.name.clone(), f.length, hex16(&f.md5)))
                .collect::<Vec<_>>()
        ),
    }
}

/// A deferred parse frames every recovery packet without hashing it
/// - the census still lists them and the set still settles - and
/// `validate_recovery_spans` then counts exactly what the hashing
/// parse counts, a corrupt packet excluded on both sides. A bad MD5
/// among the OTHER packets falls back to the hashing walk and
/// defers nothing.
#[test]
fn a_deferred_parse_settles_to_the_same_recovery_count_once_validated() {
    let set = [0x7Eu8; 16];
    let fid = [0x42u8; 16];
    let mut vol = pkt(set, TYPE_MAIN, &main_ids(64, &[fid]));
    vol.extend(pkt(set, TYPE_FILEDESC, &desc_body(fid, 0xDD, 192, "c.bin")));
    for e in 0..3u32 {
        vol.extend(pkt(set, TYPE_RECVSLIC, &slice_body(e, e as u8 + 1)));
    }
    // Corrupt the middle recovery packet's payload (the last byte of
    // the file is the third packet's; step back one packet).
    let packet_len = pkt(set, TYPE_RECVSLIC, &slice_body(0, 0)).len();
    let mut broken = vol.clone();
    let last = broken.len() - packet_len - 1;
    broken[last] ^= 0xFF;

    let hashing = Par2Set::parse(&[&broken]).expect("set parses");
    assert_eq!(
        hashing.recovery_blocks_seen, 2,
        "the hashing parse drops the corrupt one"
    );

    let (deferred, census, spans) = Par2Set::parse_deferred(&[&broken]);
    let deferred = deferred.expect("the deferred parse settles the same set");
    assert_eq!(deferred.recovery_set_id, set);
    assert_eq!(deferred.files.len(), 1);
    assert_eq!(
        deferred.recovery_blocks_seen, 0,
        "nothing counted before validation"
    );
    assert_eq!(
        spans[0].len(),
        3,
        "every recovery packet framed, the corrupt one too"
    );
    assert_eq!(
        census[0]
            .iter()
            .filter(|p| p.recovery_exponent.is_some())
            .count(),
        3,
        "the census lists what the headers say"
    );
    let found = validate_recovery_spans(&broken, &spans[0], &set, 64);
    assert_eq!(found.len(), 2, "validation drops the corrupt packet");
    assert!(found.contains_key(&0) && found.contains_key(&2));

    // A corrupt NON-recovery packet: the deferring walk falls back to
    // the hashing scan over the whole input and defers nothing.
    let mut broken_desc = vol.clone();
    let desc_at = pkt(set, TYPE_MAIN, &main_ids(64, &[fid])).len() + 70;
    broken_desc[desc_at] ^= 0xFF;
    let (fell_back, _, spans) = Par2Set::parse_deferred(&[&broken_desc]);
    assert!(spans[0].is_empty(), "the fallback verified everything");
    assert_eq!(fell_back.expect("still a set").recovery_blocks_seen, 3);
}

/// A deferred parse over inputs where ONE fell back to the hashing
/// walk and another deferred: the two populations overlap, so the
/// count the caller settles must not add the same exponent twice.
///
/// This is the shape `parfast v -q` reads as repair power that is
/// not there. Reproduced end to end at 618ca2042 against
/// par2cmdline 1.2.0: leading junk on the index declines the seeking
/// walk (which is what routes the load through `parse_deferred` at
/// all), a corrupt Creator packet in one volume sends THAT file down
/// the hashing scan, and a byte-copy of the other volume gives both
/// files the same exponent. Two blocks damaged, one unique recovery
/// block: the reference exits 2, and the engine exited 1.
///
/// The distinct-exponent half of the loop is the control that stops
/// the fix being "take the larger of the two populations": there,
/// the two really do add.
#[test]
fn mixed_deferred_and_fallback_scans_count_duplicate_exponents_once() {
    let set = [0x7Eu8; 16];
    let fid = [0x42u8; 16];
    let mut critical = pkt(set, TYPE_MAIN, &main_ids(64, &[fid]));
    critical.extend(pkt(set, TYPE_FILEDESC, &desc_body(fid, 0xDD, 192, "c.bin")));
    let shared = pkt(set, TYPE_RECVSLIC, &slice_body(0, 1));

    // The falling-back input: a Creator packet whose stored MD5 no
    // longer matches its body, so `scan_packets_deferring` gives up
    // on the whole file and hashes it, recovery packets included.
    let mut bad_creator = pkt(set, b"PAR 2.0\0Creator\0", b"test");
    bad_creator[16] ^= 1;
    let mut fallback = critical.clone();
    fallback.extend(bad_creator);
    fallback.extend(&shared);

    for (extra, want) in [(None, 1u32), (Some(1u32), 2)] {
        // The deferring input carries the SAME exponent 0, plus (in
        // the control arm) one the fallback does not have.
        let mut deferring = critical.clone();
        deferring.extend(&shared);
        if let Some(e) = extra {
            deferring.extend(pkt(set, TYPE_RECVSLIC, &slice_body(e, 2)));
        }
        // Both orders: the fix must not depend on which input the
        // walk reaches first.
        for inputs in [
            [fallback.as_slice(), deferring.as_slice()],
            [deferring.as_slice(), fallback.as_slice()],
        ] {
            let truth = Par2Set::parse(&inputs).expect("the hashing parse settles the set");
            assert_eq!(truth.recovery_blocks_seen, want as usize);

            let (actual, _, spans) = Par2Set::parse_deferred(&inputs);
            let mut settled = actual.expect("a set").recovery_blocks_seen;
            let mut exps = HashMap::new();
            for (input, spans) in inputs.iter().zip(&spans) {
                exps.extend(validate_recovery_spans(input, spans, &set, 64));
            }
            settled += exps.len();
            assert_eq!(
                settled,
                truth.recovery_blocks_seen,
                "the deferred settle must equal the hashing parse \
                     (extra exponent {extra:?}, {} deferred span(s))",
                spans.iter().map(Vec::len).sum::<usize>(),
            );
        }
    }
}

/// The seeking walk frames a volume without reading its recovery
/// payloads: the critical packets come back whole and parse to the
/// same set, every recovery packet is reported by span with its
/// header claims, and `validate_recovery_file` over those spans
/// counts what the hashing parse counts (a corrupt packet excluded).
/// A byte out of place between packets makes the walk decline.
#[test]
fn the_seeking_walk_frames_a_volume_without_its_payloads() {
    let set = [0x3Cu8; 16];
    let fid = [0x44u8; 16];
    let mut vol = pkt(set, TYPE_MAIN, &main_ids(64, &[fid]));
    vol.extend(pkt(set, TYPE_FILEDESC, &desc_body(fid, 0xDD, 192, "d.bin")));
    let critical_len = vol.len();
    for e in 0..3u32 {
        vol.extend(pkt(set, TYPE_RECVSLIC, &slice_body(e, e as u8 + 7)));
    }
    vol.extend(pkt(set, b"PAR 2.0\0Creator\0", b"who\0"));
    let packet_len = pkt(set, TYPE_RECVSLIC, &slice_body(0, 0)).len();
    let corrupt_at = critical_len + packet_len + 70; // inside the second recovery packet's body
    vol[corrupt_at] ^= 0xFF;

    let dir = std::env::temp_dir().join(format!("parfast-sparse-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("set.vol00+3.par2");
    std::fs::write(&path, &vol).unwrap();
    let f = std::fs::File::open(&path).unwrap();
    let frame = sparse_frame(&f, vol.len() as u64).expect("a well-formed volume frames");
    assert_eq!(frame.recovery.len(), 3);
    assert_eq!(frame.recovery[0].offset as usize, critical_len);
    assert_eq!(frame.recovery[1].exponent, Some(1));
    assert_eq!(
        frame.bytes.len(),
        vol.len() - 3 * packet_len,
        "the critical packets whole, nothing of the recovery payloads"
    );
    let parsed = Par2Set::parse(&[&frame.bytes]).expect("critical packets parse");
    assert_eq!(parsed.recovery_set_id, set);
    assert_eq!(parsed.recovery_blocks_seen, 0);
    let spans: Vec<(u64, u64)> = frame.recovery.iter().map(|r| (r.offset, r.len)).collect();
    let found = validate_recovery_file(&path, &spans, &set, 64);
    assert_eq!(
        found.len(),
        2,
        "the corrupt packet is dropped at validation"
    );
    assert_eq!(Par2Set::parse(&[&vol]).unwrap().recovery_blocks_seen, 2);

    // A stray byte between two packets: the walk declines, the
    // whole-read path (which resyncs) takes over.
    let mut shifted = vol[..critical_len].to_vec();
    shifted.push(0);
    shifted.extend_from_slice(&vol[critical_len..]);
    let path2 = dir.join("shifted.par2");
    std::fs::write(&path2, &shifted).unwrap();
    let f2 = std::fs::File::open(&path2).unwrap();
    assert!(sparse_frame(&f2, shifted.len() as u64).is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

/// X5-14. A physical `.par2` whose FIRST valid packet belongs to set A
/// and whose remainder is a complete set B describes B. Binding the
/// identity to the first packet filed the whole file under A, and the
/// A group then reparsed to `MixedRecoverySets` - so B vanished.
#[test]
fn a_stray_foreign_packet_does_not_hide_the_set_it_precedes() {
    let a = [0xA5u8; 16];
    let b = [0x5Bu8; 16];
    let fid = [0x31u8; 16];

    let mut mixed = pkt(a, b"PAR 2.0\0Creator\0", b"someone-else\0\0\0\0");
    mixed.extend(pkt(b, TYPE_MAIN, &main_ids(100, &[fid])));
    mixed.extend(pkt(b, TYPE_FILEDESC, &desc_body(fid, 0xDD, 400, "b.bin")));
    mixed.extend(pkt(b, TYPE_RECVSLIC, &slice_body(0, 0x11)));

    assert_eq!(
        Par2Set::set_id_of(&mixed),
        Some(b),
        "grouped under the Main"
    );
    let set = Par2Set::parse(&[&mixed]).expect("set B is still described");
    assert_eq!(set.recovery_set_id, b);
    assert_eq!(set.files.len(), 1);
    assert_eq!(set.files[0].name, "b.bin");

    // Two sets that BOTH claim to be one are still a post to group,
    // which is the case `live::pick_sets` acts on - and the answer
    // must not depend on which index was concatenated first.
    let a_index = {
        let mut v = pkt(a, TYPE_MAIN, &main_ids(200, &[fid]));
        v.extend(pkt(a, TYPE_FILEDESC, &desc_body(fid, 0xEE, 900, "a.bin")));
        v
    };
    let mut both = a_index.clone();
    both.extend_from_slice(&mixed);
    assert_eq!(
        Par2Set::parse(&[&both]).unwrap_err(),
        Par2Error::MixedRecoverySets,
        "two Main-bearing sets in one buffer are grouped, not merged"
    );
    assert_eq!(
        Par2Set::parse(&[&mixed, &a_index]).unwrap_err(),
        Par2Error::MixedRecoverySets
    );
}

/// X5-14, classification arm. A recovery VOLUME carries no Main at
/// all, so the tie-break that decides it is bytes - and a stray
/// foreign packet is a rounding error against a volume's own slices.
#[test]
fn set_id_of_a_volume_follows_the_bytes_not_the_first_packet() {
    let a = [0xA5u8; 16];
    let b = [0x5Bu8; 16];
    let mut vol = pkt(a, b"PAR 2.0\0Creator\0", b"noise\0\0\0");
    for e in 0..4u32 {
        vol.extend(pkt(b, TYPE_RECVSLIC, &slice_body(e, e as u8)));
    }
    assert_eq!(Par2Set::set_id_of(&vol), Some(b));
    assert_eq!(Par2Set::set_id_of(b"not a par2 file"), None);

    // Where the two rules DISAGREE, the Main packet wins - and this
    // is the case that makes the rule load-bearing rather than
    // decorative, so it is pinned separately. A file that is mostly
    // set A's slices but carries set B's index describes B, because
    // that is the set `Par2Set::parse` will hand back out of these
    // same bytes: `pick_sets` files the buffer under this key and
    // then parses the group, so a key that disagreed with the parse
    // would file a set under an id that is not its own.
    let mut most_bytes_a = Vec::new();
    for e in 0..8u32 {
        most_bytes_a.extend(pkt(a, TYPE_RECVSLIC, &slice_body(e, e as u8)));
    }
    let fid = [0x51u8; 16];
    most_bytes_a.extend(pkt(b, TYPE_MAIN, &main_ids(64, &[fid])));
    most_bytes_a.extend(pkt(b, TYPE_FILEDESC, &desc_body(fid, 0x77, 64, "b.bin")));
    assert_eq!(
        Par2Set::set_id_of(&most_bytes_a),
        Some(b),
        "the set with the Main packet is the set parse describes"
    );
    assert_eq!(
        Par2Set::parse(&[&most_bytes_a])
            .expect("the indexed set is described")
            .recovery_set_id,
        b,
        "the grouping key and the parse must agree on one buffer"
    );
}

/// X5-15. Repair power is DISTINCT EXPONENTS, not packets. Two
/// checksum-valid slices at exponent 0 with different bytes are two
/// packet MD5s and one row of the coding matrix; the planner sizes
/// its fetch on this number, and the native repair catalog dedupes by
/// exponent, so counting packets advertises capacity that is not
/// there and escalates into fetching every remaining volume.
///
/// Asserted on `recovery_blocks_seen` alone since Y4b deleted
/// `Par2Set::recovery_block_count`, which is what this pinned first.
/// That function took only BYTES, so it could not know a block size
/// and could not apply [`slice_fits_block`] - and no production
/// caller had ever named it. This field is what the planner actually
/// reads, so the rule is pinned where it is consumed.
#[test]
fn duplicate_recovery_exponents_are_one_block_of_capacity() {
    let set = [0x5Au8; 16];
    let fid = [0x41u8; 16];
    let mut index = pkt(set, TYPE_MAIN, &main_ids(64, &[fid]));
    index.extend(pkt(set, TYPE_FILEDESC, &desc_body(fid, 0xFF, 64, "x.bin")));

    let mut vol = pkt(set, TYPE_RECVSLIC, &slice_body(0, 0x11));
    vol.extend(pkt(set, TYPE_RECVSLIC, &slice_body(0, 0x22)));
    let one = Par2Set::parse(&[&index, &vol]).expect("parses");
    assert_eq!(one.recovery_blocks_seen, 1);

    // A genuinely different exponent is genuinely more capacity, and
    // the count is over the WHOLE parse - across inputs as within one.
    vol.extend(pkt(set, TYPE_RECVSLIC, &slice_body(1, 0x33)));
    let two = Par2Set::parse(&[&index, &vol]).expect("parses");
    assert_eq!(two.recovery_blocks_seen, 2);
}

/// Y4b. The other half of the same field, and the direction that is
/// UNSAFE. A RecvSlic short of one `block_size` cannot serve a block
/// and both SELECTION sites refuse it, but the only length test on
/// this path was `body.len() >= 4` - "carries an exponent" - so the
/// set advertised repair power for every exponent MENTIONED.
/// `get::settle` seeds each set's `on_hand` off this field, so an
/// over-count makes `needed = damage - on_hand` too SMALL and the
/// exact-fit fetch buys too little; the repair still lands, off the
/// last-resort escalation that buys every remaining volume.
///
/// The three arms are the rule: exactly one block short is refused,
/// an EMPTY payload is refused, and the two directions are not
/// symmetric - an over-long packet still counts, exactly as
/// [`slice_fits_block`] says the selection sites read it.
#[test]
fn a_recovery_slice_shorter_than_the_block_is_no_repair_power() {
    let set = [0x5Au8; 16];
    let fid = [0x41u8; 16];
    let mut index = pkt(set, TYPE_MAIN, &main_ids(64, &[fid]));
    index.extend(pkt(set, TYPE_FILEDESC, &desc_body(fid, 0xFF, 64, "x.bin")));
    // Payload lengths stay 4-byte aligned - `pkt` asserts it, and a
    // real producer's packets are padded to that boundary anyway.
    let sized = |exp: u32, data: usize| {
        let mut b = exp.to_le_bytes().to_vec();
        b.extend_from_slice(&vec![0x11u8; data]);
        pkt(set, TYPE_RECVSLIC, &b)
    };
    let seen = |data: usize| {
        let mut vol = Vec::new();
        for e in 0..4u32 {
            vol.extend(sized(e, data));
        }
        Par2Set::parse(&[&index, &vol])
            .expect("parses")
            .recovery_blocks_seen
    };
    assert_eq!(seen(64), 4, "a slice of exactly one block serves it");
    assert_eq!(seen(68), 4, "an over-long slice is cut to the block");
    assert_eq!(seen(60), 0, "four bytes short of a block serves nothing");
    assert_eq!(seen(0), 0, "an empty payload is not one block of parity");
}

/// Y4b. LONGEST-WINS at one exponent, which is what keeps this count
/// agreeing with the selection sites: they filter by
/// [`slice_fits_block`] and only THEN dedupe by exponent, so a full
/// slice sitting beside a short one at the same exponent is a row the
/// set can serve. First-seen would answer 0 or 1 depending on packet
/// order, and the meaning of a set must not turn on that (W4-10).
#[test]
fn a_short_and_a_full_slice_at_one_exponent_are_one_block() {
    let set = [0x5Au8; 16];
    let fid = [0x41u8; 16];
    let mut index = pkt(set, TYPE_MAIN, &main_ids(64, &[fid]));
    index.extend(pkt(set, TYPE_FILEDESC, &desc_body(fid, 0xFF, 64, "x.bin")));
    let sized = |exp: u32, data: usize, fill: u8| {
        let mut b = exp.to_le_bytes().to_vec();
        b.extend_from_slice(&vec![fill; data]);
        pkt(set, TYPE_RECVSLIC, &b)
    };
    for (a, b, label) in [(60, 64, "short first"), (64, 60, "full first")] {
        let mut vol = sized(0, a, 0x11);
        vol.extend(sized(0, b, 0x22));
        assert_eq!(
            Par2Set::parse(&[&index, &vol])
                .expect("parses")
                .recovery_blocks_seen,
            1,
            "{label}"
        );
    }
}

/// A hostile poster can declare a 1000-block file and ship an IFSC
/// listing ONE block. Live verify sizes its per-block state from the
/// list, so a grid shorter than the file would check slice 0, find no
/// bad blocks, and report the file clean while the other 999 MiB were
/// never posted. The grid therefore always spans the declared length:
/// a long list is trimmed to it, and a short one is filled out with
/// [`BlockCheck::UNPROVEN`], which no bytes can satisfy - so the
/// slices the packet never described still force the whole-file MD5.
///
/// This used to DROP the packet outright, which met the same hazard
/// and cost every slice's evidence with it; see [`fit_ifsc`] for what
/// that cost a repair. It was named `short_ifsc_is_dropped_not_trusted`
/// while it did.
#[test]
fn a_short_ifsc_never_vouches_past_what_it_describes() {
    let set_id = [7u8; 16];
    let fid = [9u8; 16];
    let block_size: u64 = 1 << 20;
    let length: u64 = 4 << 20; // 4 blocks

    let mut main = Vec::new();
    main.extend_from_slice(&block_size.to_le_bytes());
    main.extend_from_slice(&1u32.to_le_bytes());
    main.extend_from_slice(&fid);

    let mut desc = Vec::new();
    desc.extend_from_slice(&fid);
    desc.extend_from_slice(&[1u8; 16]); // md5
    desc.extend_from_slice(&[2u8; 16]); // md5_16k
    desc.extend_from_slice(&length.to_le_bytes());
    desc.extend_from_slice(b"data.bin");

    // Entries are distinguishable from a placeholder, or the point
    // of the assertions below could not be made: `0xNN` repeated is
    // never the all-zero MD5 `UNPROVEN` carries.
    let ifsc = |n: usize| {
        let mut b = fid.to_vec();
        for i in 0..n {
            b.extend_from_slice(&[i as u8 + 1; 16]);
            b.extend_from_slice(&(i as u32).to_le_bytes());
        }
        b
    };

    let build = |n: usize| {
        let mut buf = pkt(set_id, TYPE_MAIN, &main);
        buf.extend(pkt(set_id, TYPE_FILEDESC, &desc));
        buf.extend(pkt(set_id, TYPE_IFSC, &ifsc(n)));
        buf
    };

    // Short list: the one entry it carries is kept, and the three
    // slices it says nothing about cannot be vouched for.
    let short = build(1);
    let set = Par2Set::parse(&[&short]).unwrap();
    assert_eq!(set.files.len(), 1);
    let b = &set.files[0].blocks;
    assert_eq!(b.len(), 4, "the grid spans the declared length");
    assert!(b[0].is_proven());
    assert!(
        b[1..].iter().all(|c| !c.is_proven()),
        "a 1-entry IFSC must not vouch for a 4-block file"
    );

    // A long list describes slices the file does not have; the
    // surplus is dropped and the file's own four are kept.
    let long = build(9);
    let b = Par2Set::parse(&[&long]).unwrap().files[0].blocks.clone();
    assert_eq!(b.len(), 4);
    assert!(b.iter().all(|c| c.is_proven()));
    assert_eq!(b, ifsc_checks_of(&long)[..4]);

    // The honest count still parses and is kept.
    assert_eq!(
        Par2Set::parse(&[&build(4)]).unwrap().files[0].blocks.len(),
        4
    );
}

/// The checks an IFSC packet in `buf` literally carries, read back
/// independently of `Par2Set::parse` so a trim can be compared
/// against the packet rather than against itself.
fn ifsc_checks_of(buf: &[u8]) -> Vec<BlockCheck> {
    let mut out = Vec::new();
    scan_packets(buf, |pkt| {
        if &pkt.ptype == TYPE_IFSC
            && let Some((_, b)) = parse_ifsc(pkt.body)
        {
            out = b;
        }
    });
    out
}

#[test]
fn block_size_bound_rejects_oversized_main() {
    // A real slice parses.
    assert!(parse_main(&main_body(768_000, 1)).is_some());
    // Exactly at the cap is still accepted…
    assert!(parse_main(&main_body(256 << 20, 1)).is_some());
    // …just past it is rejected (would OOM the verifier otherwise).
    assert!(parse_main(&main_body((256 << 20) + 4, 1)).is_none());
    // The crafted 2^62-ish value that drove the out-of-memory kill.
    assert!(parse_main(&main_body(0x7FFF_FFFF_FFFF_FFFC, 1)).is_none());
    // Existing guards still hold: zero, and non-multiple-of-4.
    assert!(parse_main(&main_body(0, 1)).is_none());
    assert!(parse_main(&main_body(1002, 1)).is_none());
}

/// M4-25 of the no-RAR matrix, decoder half. `parse_main` above bounds
/// the block size from ABOVE; nothing bounds it from BELOW, so a set
/// may declare `block_size = 4` and turn a modest member into hundreds
/// of thousands of IFSC entries and that many live-verify cells. The
/// row predicted the allocator or the verifier would blow up.
///
/// It cannot arrive from a creator: par2cmdline REFUSES above 32768
/// source blocks ("Too many source blocks (262144 > 32768)", measured
/// on this box 30 Aug 2026), which is exactly why the hostile shape has
/// to be hand-built here rather than through `par2 create` - and why
/// the decoder is the only thing standing in front of it.
///
/// MEASURED CLEAN (wave-5 verification round, 30 Aug 2026): a 1 MiB
/// member at 4-byte blocks parses its 262144 cells in 71 ms and takes
/// a live activate plus a full 1 MiB feed in 117 ms.
///
/// The row allows EITHER answer - refuse below a floor, or accept and
/// bound the work - so this holds the disjunction rather than today's
/// half of it: a floor added later is a fix, not a regression, and must
/// not redden this. The 65536-byte CONTROL is what stops that arm being
/// a free pass, since a parser that refused every set would otherwise
/// read as "a floor was added".
///
/// What the accepting arm pins is the SHAPE and not the timings: one
/// cell per declared block and not one more, which IS the memory bound,
/// because a cell is fixed-size and that list is all the state there is
/// to hold. The elapsed check is a deliberate backstop, not a perf
/// assertion - `hostile_overlapping_magics_do_not_hash_quadratically`
/// above records that a 5s bound in this file failed reproducibly on a
/// loaded box, so this one is ~300x the measured cost and exists only
/// to catch the row's actual prediction of "minutes".
#[test]
fn a_four_byte_block_size_is_bounded_by_the_ifsc_it_must_carry() {
    const LEN: u64 = 1 << 20;
    let set_id = [0x25u8; 16];
    let fid = [0x26u8; 16];

    // One whole set at a chosen slice: Main, FileDesc, and an IFSC
    // carrying the honest one-entry-per-block list that size implies.
    let build = |block_size: u64| {
        let blocks = (LEN / block_size) as usize;
        let mut main = block_size.to_le_bytes().to_vec();
        main.extend_from_slice(&1u32.to_le_bytes());
        main.extend_from_slice(&fid);

        let mut desc = fid.to_vec();
        desc.extend_from_slice(&[0x27u8; 16]); // md5
        desc.extend_from_slice(&[0x28u8; 16]); // md5_16k
        desc.extend_from_slice(&LEN.to_le_bytes());
        desc.extend_from_slice(b"Tiny.Blocks.bin");
        desc.push(0); // 4-byte align the name region

        let mut ifsc = Vec::with_capacity(16 + blocks * 20);
        ifsc.extend_from_slice(&fid);
        for i in 0..blocks {
            let cell: [u8; 16] = Md5::digest((i as u64).to_le_bytes()).into();
            ifsc.extend_from_slice(&cell);
            ifsc.extend_from_slice(&(i as u32).to_le_bytes());
        }

        let mut buf = pkt(set_id, TYPE_MAIN, &main);
        buf.extend(pkt(set_id, TYPE_FILEDESC, &desc));
        buf.extend(pkt(set_id, TYPE_IFSC, &ifsc));
        (buf, blocks)
    };

    // The control: an ordinary slice over the same member. Whatever
    // happens below, THIS must parse into its 16 cells - so a refusal
    // of the 4-byte set is a floor and never a broken parser.
    let (sane, sane_blocks) = build(65536);
    let ok = Par2Set::parse(&[&sane]).expect("an ordinary 64 KiB slice must parse");
    assert_eq!(
        ok.files[0].blocks.len(),
        sane_blocks,
        "the control set must reach its IFSC, or the arm below proves nothing"
    );

    const BLOCKS: usize = (LEN / 4) as usize;
    let (hostile, blocks) = build(4);
    assert_eq!(blocks, BLOCKS);

    let t = std::time::Instant::now();
    let Ok(parsed) = Par2Set::parse(&[&hostile]) else {
        // A block-size floor was added. That is the row's other
        // acceptable answer and there is no work left to bound.
        return;
    };
    assert_eq!(parsed.block_size, 4, "the declared slice must survive");
    assert_eq!(
        parsed.files.len(),
        1,
        "one FileDesc in, one file out - a fan-out here is the blow-up"
    );
    assert_eq!(
        parsed.files[0].blocks.len(),
        BLOCKS,
        "{BLOCKS} declared blocks must yield exactly {BLOCKS} cells - \
             fewer means the IFSC was dropped and this arm pins nothing, \
             more means the state is not bounded by the input"
    );

    // The live verifier sizes its per-block state from that list, so
    // activating and feeding the whole member is where a per-cell cost
    // would show. Fed in ONE call on purpose: a chunked feed would let
    // a per-call walk of all 262144 cells hide in the chunk count.
    let v = crate::live::LiveVerifier::new(1);
    v.set_name_hint(0, "Tiny.Blocks.bin");
    v.activate(&[&hostile])
        .expect("the set the parser just accepted must also activate");
    v.on_data(0, "Tiny.Blocks.bin", LEN, 0, &vec![0u8; LEN as usize]);
    let secs = t.elapsed().as_secs_f64();

    assert!(
        secs < 60.0,
        "a hand-crafted 4-byte-block set over a {LEN}-byte member cost \
             {secs:.1}s to parse, activate and feed ({BLOCKS} cells) - the \
             missing block-size floor has stopped being harmless"
    );
}

#[test]
fn a_wrapping_file_count_is_refused_not_accepted() {
    // Hand-built rather than through `main_body`, which sizes its id
    // list to the count - the point here is a count the body cannot
    // back. nfiles * 16 == 2^32 WRAPS to 0 in a 32-bit usize
    // multiply, so the old `ids_bytes.len() < nfiles * 16` guard
    // passed a tiny crafted Main packet on ARMv7 (and panicked under
    // overflow-checks, which is what a fuzzer on a 32-bit host would
    // have hit). The division form cannot wrap on any width (review
    // sweep 24 Aug, F-02).
    let body = |nfiles: u32| {
        let mut b = Vec::new();
        b.extend_from_slice(&768_000u64.to_le_bytes());
        b.extend_from_slice(&nfiles.to_le_bytes());
        b.extend_from_slice(&[0u8; 16]); // one id, however many claimed
        b
    };
    assert!(parse_main(&body(0x1000_0000)).is_none());
    assert!(parse_main(&body(u32::MAX)).is_none());
    // ...and an honest count over the same 16-byte list still parses.
    assert_eq!(parse_main(&body(1)).unwrap().1.len(), 1);
}

/// The three block figures, and which way each of them leans.
///
/// A verdict that STOPS a download compares a FLOOR on the damage
/// against a CEILING on the cure, so the estimate that sits between
/// them may never be substituted for either. Real numbers from the
/// 15 Aug post: 1,614,720-byte slices, and volumes the repair path
/// found held 40 blocks between them.
#[test]
fn the_recovery_bounds_never_cross_the_estimate() {
    const BLOCK: u64 = 1_614_720;
    let volumes = [
        1_708_175u64,
        3_415_979,
        6_790_307,
        13_497_147,
        15_163_522,
        26_869_479,
    ];
    let est: usize = volumes.iter().map(|&b| est_recovery_blocks(b, BLOCK)).sum();
    let ceil: u64 = volumes.iter().map(|&b| max_recovery_blocks(b, BLOCK)).sum();
    assert_eq!(est, 40, "the estimate reproduces the budget repair found");
    assert_eq!(ceil, 40u64);
    // The ceiling can never come in under the estimate - that is the
    // only relationship a verdict may lean on.
    for &b in &volumes {
        assert!(
            max_recovery_blocks(b, BLOCK) >= est_recovery_blocks(b, BLOCK) as u64,
            "{b} bytes: ceiling below estimate"
        );
    }
    // A volume too small for one slice holds none, however named.
    assert_eq!(max_recovery_blocks(41_901, BLOCK), 0);
    assert_eq!(est_recovery_blocks(41_901, BLOCK), 0);
    // A zero block size is not a set: every figure is zero rather
    // than a division by it.
    assert_eq!(max_recovery_blocks(1 << 30, 0), 0);
    assert_eq!(est_recovery_blocks(1 << 30, 0), 0);
    assert_eq!(min_damaged_blocks(1 << 30, 0), 0);
}

/// Missing bytes cannot hide in fewer slices than they fill. The
/// count rounds DOWN, one step further from claiming impossibility
/// than the true bound (which is the ceiling) already is.
#[test]
fn missing_bytes_force_at_least_that_many_damaged_blocks() {
    assert_eq!(min_damaged_blocks(0, 4_096), 0);
    assert_eq!(min_damaged_blocks(1, 4_096), 0);
    assert_eq!(min_damaged_blocks(4_095, 4_096), 0);
    assert_eq!(min_damaged_blocks(4_096, 4_096), 1);
    assert_eq!(min_damaged_blocks(4_097, 4_096), 1);
    // The 15 Aug post: 1.45 GB gone, 1.6 MB slices. RAW bytes -
    // feeding this the NZB's encoded figure is the units error
    // [`min_raw_bytes`] exists to stop.
    assert_eq!(min_damaged_blocks(1_453_188_000, 1_614_720), 899);
}

/// The encoded-to-raw conversion has one job: never overstate the
/// raw payload, because everything downstream of it is a damage
/// FLOOR that stops a download.
///
/// The 15 Aug post is the measurement it is set against -
/// 3,332,350,599 encoded bytes over 3,229,432,857 raw ones, 3.19%
/// overhead where [`YENC_RAW_FRACTION`] allows 2%. Whole-file damage
/// is where an overstatement shows up as an outright impossibility:
/// the file has 2,000 slices and the unconverted figure claimed
/// 2,063 of them damaged.
#[test]
fn encoded_bytes_convert_to_a_raw_floor_the_real_post_clears() {
    const ENCODED: u64 = 3_332_350_599;
    const RAW: u64 = 3_229_432_857;
    const BLOCK: u64 = 1_614_720;

    assert!(
        min_raw_bytes(ENCODED) <= RAW,
        "the floor overstates the payload it is a floor for"
    );
    assert!(
        min_damaged_blocks(min_raw_bytes(ENCODED), BLOCK) <= RAW.div_ceil(BLOCK),
        "whole-file damage claimed more blocks than the file has"
    );
    // And it gives up only the overhead: a bound that threw the
    // deficit away would be safe and useless.
    assert!(min_raw_bytes(ENCODED) * 10 >= RAW * 9);
    // 0.98 is the ESTIMATE fraction and would not have caught this
    // post - the reason a second, blunter constant exists at all.
    assert!((ENCODED as f64 * YENC_RAW_FRACTION) as u64 > RAW);

    assert_eq!(min_raw_bytes(0), 0);
}

/// The Main packet of a real par2 index states the slice size in its
/// first 92 bytes - which is what makes the pre-flight probe one
/// small article rather than a download.
#[test]
fn a_real_index_states_its_block_size_in_its_first_bytes() {
    const INDEX: &[u8] = include_bytes!("../../tests/fixtures/par2/testset.par2");
    let set = Par2Set::parse(&[INDEX]).expect("fixture is a valid set");
    assert_eq!(set.block_size, 4_096);
    // And from the head alone: the Main packet is the first thing in
    // the file, so a partial read is enough.
    let head = Par2Set::parse(&[&INDEX[..256]]).expect("Main packet is in the first bytes");
    assert_eq!(head.block_size, 4_096);
}

/// Both verdict bounds must survive a quotient past 2^32.
///
/// They used to narrow the u64 quotient with `as usize`, which is a
/// silent truncation of the low 32 bits on a 32-bit target - and we
/// ship one (`armv7-unknown-linux-musleabihf`). `encoded_bytes` is
/// the NZB's poster-controlled `bytes=` with no cap on this path and
/// `parse_main` admits a block size as small as 4, so 16 GiB
/// declared on one volume wraps the CEILING to zero and any deficit
/// at all becomes a false IMPOSSIBLE - refusing a job that would
/// have finished, which is the exact direction these two functions
/// exist to forbid. Keeping the arithmetic in u64 makes the
/// truncation unrepresentable; on a 64-bit host this test cannot
/// fail either way, so it is here as the shape guard, not as proof.
#[test]
fn the_verdict_bounds_do_not_wrap_at_a_32_bit_quotient() {
    const WRAP: u64 = 1 << 32;
    // A ceiling of exactly 2^32 blocks: the value `as usize`
    // truncated to 0 on armv7.
    let ceiling: u64 = max_recovery_blocks(4 * WRAP, 4);
    assert_eq!(ceiling, WRAP);
    assert!(
        ceiling > u32::MAX as u64,
        "the guard needs a wrapping value"
    );
    // The deficit half wrapped DOWN, which softens rather than
    // condemns - but it is the same cast and the same fix.
    assert_eq!(min_damaged_blocks(4 * WRAP, 4), WRAP);
    // And the ordering the whole module rests on holds across the
    // boundary: equal bytes on both sides never condemns.
    assert!(min_damaged_blocks(4 * WRAP, 4) <= max_recovery_blocks(4 * WRAP, 4));
}

// -- streaming vs buffered verification -------------------------------
//
// `verify_file` stays the reference implementation (see its docs and
// `verify_file_blocks`'). `verify_file_streaming` is the one the
// download and CLI paths actually run, so every verdict it reaches has
// to be the reference's verdict, byte for byte. The fixture-driven
// half of this differential - real par2cmdline output, choked reads,
// corrupt/short/empty inputs - lives in tests/integration/par2_parse.rs; this half
// covers what a 33 KiB fixture cannot reach: a file several read
// windows long, whose blocks straddle those windows at an offset that
// never repeats.

/// A `Par2File` describing `data` exactly, with honest per-block
/// checksums (last block zero-padded per spec). Deliberately built
/// with the plain one-shot hashers rather than with either verifier,
/// so it is an independent third party to the comparison.
fn synth_file(data: &[u8], bs: usize) -> Par2File {
    let mut padded = vec![0u8; bs];
    let blocks = (0..data.len().div_ceil(bs))
        .map(|i| {
            let start = i * bs;
            let end = (start + bs).min(data.len());
            padded.fill(0);
            padded[..end - start].copy_from_slice(&data[start..end]);
            BlockCheck {
                md5: Md5::digest(&padded).into(),
                crc32: crc32fast::hash(&padded),
            }
        })
        .collect();
    Par2File {
        file_id: [0u8; 16],
        name: "synth.bin".into(),
        length: data.len() as u64,
        md5: Md5::digest(data).into(),
        md5_16k: Md5::digest(&data[..data.len().min(HASH16K_LEN)]).into(),
        blocks,
    }
}

fn assert_agrees(file: &Par2File, block_size: u64, data: &[u8], case: &str) {
    static NEXT_PATH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let want = verify_file(file, block_size, data);
    let got = verify_file_streaming(file, block_size, std::io::Cursor::new(data))
        .expect("a cursor cannot fail to read");
    let seekable = verify_file_seekable(file, block_size, std::io::Cursor::new(data))
        .expect("a cursor cannot fail to seek or read");
    let path = std::env::temp_dir().join(format!(
        "nzbkit-par2-path-differential-{}-{}",
        std::process::id(),
        NEXT_PATH.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
    ));
    std::fs::write(&path, data).expect("write path-verifier fixture");
    let path_got = verify_file_path(&path, file, block_size, 8)
        .expect("a regular fixture file cannot fail to read");
    let path_md5_got =
        verify_file_md5_path(&path, file).expect("a regular fixture file cannot fail to read");
    let _ = std::fs::remove_file(path);
    assert_eq!(want.blocks, got.blocks, "{case}: per-block flags");
    assert_eq!(want.md5_ok, got.md5_ok, "{case}: whole-file MD5");
    assert_eq!(want.md5_16k_ok, got.md5_16k_ok, "{case}: MD5-16k");
    assert_eq!(want.blocks, seekable.blocks, "{case}: seekable blocks");
    assert_eq!(want.md5_ok, seekable.md5_ok, "{case}: seekable MD5");
    assert_eq!(
        want.md5_16k_ok, seekable.md5_16k_ok,
        "{case}: seekable MD5-16k"
    );
    assert_eq!(want.blocks, path_got.blocks, "{case}: file-path blocks");
    assert_eq!(want.md5_ok, path_got.md5_ok, "{case}: file-path MD5");
    assert_eq!(
        want.md5_16k_ok, path_got.md5_16k_ok,
        "{case}: file-path MD5-16k"
    );
    assert_eq!(
        want.md5_ok,
        verify_file_md5_streaming(file, std::io::Cursor::new(data))
            .expect("a cursor cannot fail to read"),
        "{case}: narrow MD5 verifier"
    );
    assert_eq!(want.md5_ok, path_md5_got, "{case}: file-path MD5 verifier");
}

struct Counted<R> {
    inner: R,
    bytes_read: usize,
}

impl<R: std::io::Read> std::io::Read for Counted<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.bytes_read += n;
        Ok(n)
    }
}

impl<R: std::io::Seek> std::io::Seek for Counted<R> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(pos)
    }
}

/// Clean is the common standalone-verify case. Its whole-file digest
/// settles every block, so reading the payload again for block hashes is
/// pure work. A damaged file still takes the diagnostic second pass.
#[test]
fn seekable_verify_only_rewinds_for_damage() {
    const BS: usize = 64 << 10;
    let data: Vec<u8> = (0..3 * BS + 117)
        .map(|i| (i as u8).wrapping_mul(29).wrapping_add((i >> 9) as u8))
        .collect();
    let file = synth_file(&data, BS);

    let mut clean = Counted {
        inner: std::io::Cursor::new(&data),
        bytes_read: 0,
    };
    let clean_v = verify_file_seekable(&file, BS as u64, &mut clean).unwrap();
    assert!(clean_v.md5_ok && clean_v.blocks.iter().all(|&ok| ok));
    assert_eq!(clean.bytes_read, data.len(), "clean must be one read pass");

    let mut hurt = data.clone();
    hurt[BS + 3] ^= 0x80;
    let mut damaged = Counted {
        inner: std::io::Cursor::new(&hurt),
        bytes_read: 0,
    };
    let damaged_v = verify_file_seekable(&file, BS as u64, &mut damaged).unwrap();
    assert!(!damaged_v.md5_ok);
    assert_eq!(
        damaged_v.blocks.iter().filter(|&&ok| !ok).count(),
        1,
        "the diagnostic pass must still identify the exact block"
    );
    assert_eq!(
        damaged.bytes_read,
        2 * data.len(),
        "damage must pay exactly one diagnostic reread"
    );

    let path = std::env::temp_dir().join(format!(
        "nzbkit-par2-parallel-verify-{}",
        std::process::id()
    ));
    std::fs::write(&path, &hurt).unwrap();
    let parallel = verify_file_path(&path, &file, BS as u64, 8).unwrap();
    assert_eq!(parallel.blocks, damaged_v.blocks);
    assert_eq!(parallel.md5_ok, damaged_v.md5_ok);
    assert_eq!(parallel.md5_16k_ok, damaged_v.md5_16k_ok);

    // The FileDesc and IFSC are separate claims. Exercise that hostile
    // pairing through the parallel path too: a matching CRC must not
    // launder a block whose IFSC MD5 disagrees.
    let mut inconsistent = file.clone();
    inconsistent.blocks[0].md5 = [0x5a; 16];
    let want = verify_file(&inconsistent, BS as u64, &hurt);
    let got = verify_file_path(&path, &inconsistent, BS as u64, 8).unwrap();
    assert_eq!(got.blocks, want.blocks, "parallel IFSC-conflict bitmap");
    assert_eq!(got.md5_ok, want.md5_ok, "parallel IFSC-conflict MD5");
    let _ = std::fs::remove_file(path);
}

/// A fitted short IFSC is a real checksum prefix followed by UNPROVEN
/// cells. Once the whole-file MD5 has failed, the suffix cannot become
/// true for any bytes, so the rewind pass owes only the prefix. Keep the
/// one-pass streamer in the same differential: it must still consume the
/// whole source for FileDesc MD5, but must return the identical bitmap.
#[test]
fn a_short_ifsc_diagnostic_reads_only_its_proven_prefix() {
    const BS: usize = 64 << 10;
    let data: Vec<u8> = (0..4 * VERIFY_CHUNK + 117)
        .map(|i| (i as u8).wrapping_mul(29).wrapping_add((i >> 9) as u8))
        .collect();
    let mut file = synth_file(&data, BS);
    const PROVEN: usize = 3;
    file.blocks[PROVEN..].fill(BlockCheck::UNPROVEN);
    // Force the diagnostic pass while leaving every proved prefix block
    // byte-exact. This is also an adversarial FileDesc/IFSC pairing: the
    // two packet claims are intentionally independent.
    file.md5[0] ^= 0x80;

    let mut seekable = Counted {
        inner: std::io::Cursor::new(&data),
        bytes_read: 0,
    };
    let got = verify_file_seekable(&file, BS as u64, &mut seekable).unwrap();
    assert!(!got.md5_ok);
    assert!(got.blocks[..PROVEN].iter().all(|&ok| ok));
    assert!(got.blocks[PROVEN..].iter().all(|&ok| !ok));
    assert_eq!(
        seekable.bytes_read,
        data.len() + PROVEN * BS,
        "the rewind pass must stop exactly after the last real IFSC cell"
    );

    let mut one_pass = Counted {
        inner: std::io::Cursor::new(&data),
        bytes_read: 0,
    };
    let streamed = verify_file_streaming(&file, BS as u64, &mut one_pass).unwrap();
    assert_eq!(streamed.blocks, got.blocks);
    assert_eq!(streamed.md5_ok, got.md5_ok);
    assert_eq!(streamed.md5_16k_ok, got.md5_16k_ok);
    assert_eq!(
        one_pass.bytes_read,
        data.len(),
        "the one-pass form still owes the complete FileDesc hashes"
    );
    assert_agrees(&file, BS as u64, &data, "short IFSC proven prefix");
}

/// Exercise the shapes a parser can hand verification after fitting a
/// malformed IFSC: no entries, a short suffix, and reserved all-zero MD5
/// entries interleaved between real checks. The buffered implementation
/// remains the oracle and the path call crosses the test-only positioned
/// threshold, so every implementation is included in each comparison.
#[test]
fn unproven_diagnostics_match_the_buffered_oracle_in_every_position() {
    const BS: usize = 131_068;
    let data: Vec<u8> = (0..2 * VERIFY_CHUNK + 19_117)
        .map(|i| (i as u8).wrapping_mul(41).wrapping_add((i >> 11) as u8))
        .collect();
    let honest = synth_file(&data, BS);
    assert!(honest.blocks.len() > 8);

    let mut disk = data.clone();
    disk[4 * BS + 17] ^= 0x5a;

    let mut no_ifsc = honest.clone();
    no_ifsc.blocks.clear();
    assert_agrees(&no_ifsc, BS as u64, &disk, "missing IFSC");

    let mut zero_entry_ifsc = honest.clone();
    zero_entry_ifsc.blocks.fill(BlockCheck::UNPROVEN);
    assert_agrees(
        &zero_entry_ifsc,
        BS as u64,
        &disk,
        "zero-entry IFSC fitted entirely with placeholders",
    );

    let mut short = honest.clone();
    short.blocks[3..].fill(BlockCheck::UNPROVEN);
    let short_want = verify_file(&short, BS as u64, &disk);
    assert_eq!(short_want.blocks[..3], [true, true, true]);
    assert!(short_want.blocks[3..].iter().all(|&ok| !ok));
    assert_agrees(&short, BS as u64, &disk, "short IFSC suffix");

    let mut mixed = honest.clone();
    for index in [0, 2, 7, mixed.blocks.len() - 1] {
        mixed.blocks[index] = BlockCheck::UNPROVEN;
    }
    let mixed_want = verify_file(&mixed, BS as u64, &disk);
    assert!(!mixed_want.blocks[0]);
    assert!(!mixed_want.blocks[2]);
    assert!(!mixed_want.blocks[4], "the damaged real check stays bad");
    assert!(mixed_want.blocks[5], "a later real check keeps its offset");
    assert!(!mixed_want.blocks[7]);
    assert!(!mixed_want.blocks[mixed.blocks.len() - 1]);
    assert_agrees(&mixed, BS as u64, &disk, "interior UNPROVEN entries");
    assert_agrees(
        &mixed,
        BS as u64,
        &disk[..2 * BS + 17],
        "EOF inside an interior UNPROVEN entry",
    );
}

/// Blocks that straddle the read window - the one thing the streaming
/// form does that the buffered form never had to. 300,004 bytes into a
/// 1 MiB window means no block boundary ever lands on a window
/// boundary, and the file spans four windows, so a block is split at
/// three different offsets within itself.
#[test]
fn streaming_verify_matches_reference_across_read_windows() {
    const BS: usize = 300_004;
    // Not a round multiple of BS: the last block is short and padded.
    let len = 3 * VERIFY_CHUNK + 7;
    let data: Vec<u8> = (0..len as u64)
        .map(|i| (i.wrapping_mul(2654435761) >> 16) as u8)
        .collect();
    let f = synth_file(&data, BS);
    assert!(f.blocks.len() > 10, "the case needs several blocks");

    // Guard the guard: with garbage checksums both implementations
    // would answer `false` everywhere and agree vacuously.
    let clean = verify_file(&f, BS as u64, &data);
    assert!(clean.blocks.iter().all(|&ok| ok) && clean.md5_ok && clean.md5_16k_ok);
    assert_agrees(&f, BS as u64, &data, "clean");

    // One flipped byte in a block that a read window splits.
    let mut hurt = data.clone();
    hurt[VERIFY_CHUNK + 3] ^= 0xff;
    let v = verify_file(&f, BS as u64, &hurt);
    assert_eq!(v.blocks.iter().filter(|ok| !**ok).count(), 1);
    assert_agrees(&f, BS as u64, &hurt, "one flipped byte");

    // A flip inside the short, zero-padded final block.
    let mut tail = data.clone();
    let last = tail.len() - 1;
    tail[last] ^= 0x01;
    assert_agrees(&f, BS as u64, &tail, "flipped tail byte");

    // Truncated mid-block, and grown past the last expected block.
    assert_agrees(&f, BS as u64, &data[..len - 5], "truncated");
    assert_agrees(&f, BS as u64, &data[..BS + 17], "truncated to one block");
    let mut longer = data.clone();
    longer.extend_from_slice(b"trailing bytes past the recovery set");
    assert_agrees(&f, BS as u64, &longer, "trailing bytes");
}
/// A Unicode Filename packet body: file id then the name in UTF-16,
/// null-padded to a multiple of 4 like every other packet body.
fn uni_body(fid: [u8; 16], name: &str, le: bool, bom: bool) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&fid);
    let mut put = |u: u16| b.extend_from_slice(&if le { u.to_le_bytes() } else { u.to_be_bytes() });
    if bom {
        put(0xFEFF);
    }
    for u in name.encode_utf16() {
        put(u);
    }
    while !b.len().is_multiple_of(4) {
        b.push(0);
    }
    b
}

// -- M4-37 / M4-38: what a packet is allowed to assert ----------------

/// A FileDesc body describing `data` truthfully under `name`, with
/// a file id the caller chooses - so a test can post an honest one,
/// or forge another file's. Named for what it does rather than
/// `desc_body`, which is a different helper in this same module.
fn desc_of(fid: [u8; 16], name: &str, data: &[u8]) -> Vec<u8> {
    let mut b = fid.to_vec();
    b.extend_from_slice(&<[u8; 16]>::from(Md5::digest(data)));
    b.extend_from_slice(&<[u8; 16]>::from(Md5::digest(
        &data[..data.len().min(HASH16K_LEN)],
    )));
    b.extend_from_slice(&(data.len() as u64).to_le_bytes());
    let mut nb = name.as_bytes().to_vec();
    nb.resize(nb.len().next_multiple_of(4), 0);
    b.extend_from_slice(&nb);
    b
}

/// The spec's file id: MD5 of the FileDesc's own hash16k, length and
/// name - the LAST three fields, without the name's null padding.
/// Confirmed against par2cmdline 1.3.0 output before it was relied on.
fn honest_fid(name: &str, data: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(Md5::digest(&data[..data.len().min(HASH16K_LEN)]));
    h.update((data.len() as u64).to_le_bytes());
    h.update(name.as_bytes());
    h.finalize().into()
}

/// An IFSC body carrying honest checks for `data`, but only `n` of
/// them - `n` short of, equal to, or past the file's real block count.
fn ifsc_body(fid: [u8; 16], data: &[u8], bs: usize, n: usize) -> Vec<u8> {
    let mut b = fid.to_vec();
    let mut padded = vec![0u8; bs];
    for i in 0..n {
        let start = i * bs;
        padded.fill(0);
        if start < data.len() {
            let end = (start + bs).min(data.len());
            padded[..end - start].copy_from_slice(&data[start..end]);
        }
        b.extend_from_slice(&<[u8; 16]>::from(Md5::digest(&padded)));
        b.extend_from_slice(&crc32fast::hash(&padded).to_le_bytes());
    }
    b
}

/// M4-21 (30 Aug 2026): a Main packet's NON-recovery file ids - the
/// "verify but do not repair" half QuickPar and MultiPar both write -
/// resolve through their FileDescs into `nonrecovery`, and NEVER into
/// `files`.
///
/// Both halves of that assertion are load-bearing and for different
/// reasons. Before this they were parsed and dropped, so the file was
/// never named, never verified and nothing said so. Putting them in
/// `files` instead would be worse than the gap: repair lays files onto
/// the global input-slice index by walking that list in order, so one
/// extra entry shifts every exponent after it.
#[test]
fn nonrecovery_file_ids_are_kept_out_of_the_recovery_set_and_still_read() {
    let set_id = [11u8; 16];
    let rec = [1u8; 16];
    let non = [2u8; 16];
    let payload: Vec<u8> = (0..64u8).collect();
    let mut buf = pkt(set_id, TYPE_MAIN, &main_ids_nonrec(4, &[rec], &[non]));
    buf.extend(pkt(
        set_id,
        TYPE_FILEDESC,
        &desc_body_over(rec, "payload.bin", &payload),
    ));
    buf.extend(pkt(
        set_id,
        TYPE_FILEDESC,
        &desc_body_over(non, "notes.nfo", b"notes"),
    ));
    let set = Par2Set::parse(&[&buf]).unwrap();
    assert_eq!(
        set.files
            .iter()
            .map(|f| f.name.as_str())
            .collect::<Vec<_>>(),
        ["payload.bin"],
        "a verify-only member must not enter the slice index space"
    );
    assert_eq!(
        set.nonrecovery
            .iter()
            .map(|f| f.name.as_str())
            .collect::<Vec<_>>(),
        ["notes.nfo"]
    );
    // The whole-file MD5 is what the naming tier finalizes on, so it
    // has to be the descriptor's own and not a placeholder.
    assert_eq!(
        set.nonrecovery[0].md5,
        <[u8; 16]>::from(Md5::digest(b"notes"))
    );
    assert_eq!(set.nonrecovery[0].length, 5);
}

/// An id listed in BOTH halves of one Main packet resolves ONCE, as a
/// recovery member. `descs.remove` is what makes that true; a `get`
/// would hand the same descriptor to repair AND to the weak naming
/// tier, which is a file being named by a tier that has no business
/// speaking about a member the set already covers.
#[test]
fn an_id_in_both_main_halves_resolves_once_as_a_recovery_member() {
    let set_id = [12u8; 16];
    let fid = [3u8; 16];
    let mut buf = pkt(set_id, TYPE_MAIN, &main_ids_nonrec(4, &[fid], &[fid]));
    buf.extend(pkt(
        set_id,
        TYPE_FILEDESC,
        &desc_body(fid, 1, 4, "both.bin"),
    ));
    let set = Par2Set::parse(&[&buf]).unwrap();
    assert_eq!(set.files.len(), 1);
    assert!(set.nonrecovery.is_empty());
}

/// M4-22 (30 Aug 2026): a MultiPar-shaped Unicode Filename packet
/// carries the real name where the FileDesc's byte field holds a
/// lossy transliteration. Bare UTF-16LE with no BOM is what producers
/// write and is the shape that must work.
#[test]
fn a_unicode_filename_packet_overrides_a_lossy_filedesc_spelling() {
    let set_id = [13u8; 16];
    let fid = [4u8; 16];
    let mut buf = pkt(set_id, TYPE_MAIN, &main_ids(4, &[fid]));
    buf.extend(pkt(
        set_id,
        TYPE_FILEDESC,
        &desc_body(fid, 0xAB, 4, "Bjork - Vesperti.mkv"),
    ));
    buf.extend(pkt(
        set_id,
        TYPE_UNIFILEN,
        &uni_body(fid, "Björk - Vespertine.mkv", true, false),
    ));
    let set = Par2Set::parse(&[&buf]).unwrap();
    assert_eq!(set.files[0].name, "Björk - Vespertine.mkv");
    // It renames and nothing else: the file id every reader keys
    // packets by, and the checksums the content tiers prove a
    // nomination with, are the FileDesc's own.
    assert_eq!(set.files[0].file_id, fid);
    assert_eq!(set.files[0].md5, [0xABu8; 16]);
    assert_eq!(set.files[0].length, 4);
}

/// A BOM is two bytes of unambiguous evidence, so it is honoured -
/// and STRIPPED. Leaving it on is a real directory entry whose name
/// starts with U+FEFF (the W4-13 defect, one file over).
#[test]
fn a_unicode_filename_packet_honours_and_strips_a_byte_order_mark() {
    for (le, label) in [(true, "LE"), (false, "BE")] {
        let set_id = [14u8; 16];
        let fid = [5u8; 16];
        let mut buf = pkt(set_id, TYPE_MAIN, &main_ids(4, &[fid]));
        buf.extend(pkt(
            set_id,
            TYPE_FILEDESC,
            &desc_body(fid, 1, 1, "ascii.mkv"),
        ));
        buf.extend(pkt(
            set_id,
            TYPE_UNIFILEN,
            &uni_body(fid, "Ünïcøde.mkv", le, true),
        ));
        let set = Par2Set::parse(&[&buf]).unwrap();
        assert_eq!(set.files[0].name, "Ünïcøde.mkv", "{label} BOM");
    }
}

/// Nothing is guessed and nothing is half-taken: a body that does not
/// decode, is empty, or carries an interior NUL is REFUSED and the
/// FileDesc's name stands. A wrong name that looks landed is the one
/// outcome neither answer may produce.
///
/// EVERY BODY HERE IS 4-ALIGNED, and that is not cosmetic. Both arms
/// of `scan_packets` refuse a packet whose declared length is not a
/// multiple of 4, so a body that is not one never reaches
/// `parse_unifilen` at all and a case built from one asserts the
/// SCANNER's rule while reporting this function's. Two of these cases
/// were written that way first and one of them then survived a
/// mutation that deleted the guard it was supposed to be about.
#[test]
fn an_undecodable_unicode_filename_packet_leaves_the_filedesc_name() {
    let set_id = [15u8; 16];
    let fid = [6u8; 16];
    let base = |extra: &[u8]| {
        let mut b = fid.to_vec();
        b.extend_from_slice(extra);
        assert!(
            (b.len() + HEADER_LEN as usize).is_multiple_of(4),
            "fixture body must survive the packet scanner"
        );
        b
    };
    let bodies: Vec<(&str, Vec<u8>)> = vec![
        // Unpaired high surrogate.
        ("unpaired surrogate", base(&[0x00, 0xD8, b'a', 0])),
        // File id only.
        ("empty", fid.to_vec()),
        // NUL between two characters - a truncation for any consumer
        // that treats the name as a C string. Padded to 4 so it is
        // this function refusing it and not the scanner.
        ("interior NUL", base(&[b'a', 0, 0, 0, b'b', 0, 0, 0])),
    ];
    for (label, body) in bodies {
        let mut buf = pkt(set_id, TYPE_MAIN, &main_ids(4, &[fid]));
        buf.extend(pkt(
            set_id,
            TYPE_FILEDESC,
            &desc_body(fid, 1, 1, "kept.mkv"),
        ));
        buf.extend(pkt(set_id, TYPE_UNIFILEN, &body));
        let set = Par2Set::parse(&[&buf]).unwrap();
        assert_eq!(set.files[0].name, "kept.mkv", "{label}");
    }
}

/// A name region that is not a whole number of code units is refused,
/// asserted at the FUNCTION because it is unreachable through
/// `Par2Set::parse`: the packet scanner's 4-alignment rule means a
/// body reaching this is always a multiple of 4 bytes, so its name
/// region is always even. The guard stays because `parse_unifilen` is
/// a crate-visible parser with its own contract, and dropping the
/// last byte in silence is the half-take this whole family refuses -
/// but a pin that pretends the scanner would deliver one is a pin
/// about the scanner.
#[test]
fn a_unicode_filename_body_of_half_a_code_unit_is_refused() {
    let fid = [6u8; 16];
    let mut body = fid.to_vec();
    body.extend_from_slice(&[b'a', 0, b'b']);
    assert!(parse_unifilen(&body).is_none());
    // The same bytes one longer DO decode, so the case is about the
    // odd byte and not about the content.
    body.push(0);
    assert_eq!(parse_unifilen(&body).unwrap().1, "ab");
}

/// The two name packets answer an interior NUL DIFFERENTLY, on
/// purpose: `parse_unifilen` refuses the name outright (M4-22) and
/// `parse_filedesc` keeps the byte and hands it downstream.
///
/// A PIN, not a defect, and the reason is at [`parse_filedesc`]:
/// refusing costs the OPTIONAL packet nothing (the FileDesc name
/// stands) and costs the REQUIRED one the whole descriptor - the
/// length and both MD5s with it - so the same strictness is right
/// at one and wrong at the other. Recorded 31 Aug 2026 because
/// "two readers of the same concept disagree" is the shape that
/// gets tidied into agreement by somebody who has not priced both
/// sides.
///
/// The interior byte is safe because the FILESYSTEM boundary maps
/// it, not the parser: `sanitize_filename_for` turns every
/// `char::is_control` into `_`, asserted here beside the parsers so
/// the two halves of the answer are read together, and end-to-end
/// by `hostile_filedesc_name_forms_land_contained_and_sanitized`.
#[test]
fn the_two_name_packets_answer_an_interior_nul_differently() {
    let fid = [9u8; 16];

    // The optional packet REFUSES. `foo\0bar` in UTF-16LE, padded to
    // a whole number of 4-byte units the way a real packet is.
    let mut uni = fid.to_vec();
    for c in "foo\0bar".chars() {
        uni.extend_from_slice(&(c as u16).to_le_bytes());
    }
    uni.extend_from_slice(&[0, 0]);
    assert!(
        parse_unifilen(&uni).is_none(),
        "M4-22: an interior NUL is refused, and the FileDesc name stands"
    );
    // Same bytes without the interior NUL DO decode, so the case is
    // about that byte and not about the encoding or the padding.
    let mut ok = fid.to_vec();
    for c in "foobar".chars() {
        ok.extend_from_slice(&(c as u16).to_le_bytes());
    }
    assert_eq!(parse_unifilen(&ok).unwrap().1, "foobar");

    // The required packet KEEPS it - 16 id + 16 md5 + 16 md5_16k +
    // 8 length, then the name null-padded to a multiple of 4.
    let mut desc = vec![9u8; 16];
    desc.extend_from_slice(&[1u8; 16]);
    desc.extend_from_slice(&[2u8; 16]);
    desc.extend_from_slice(&99u64.to_le_bytes());
    desc.extend_from_slice(b"foo\0bar.mkv");
    let (_, d) = parse_filedesc(&desc).expect("a descriptor is never dropped over its name");
    assert_eq!(d.name, "foo\0bar.mkv");
    assert_eq!(d.length, 99, "the fields a refusal would have cost");

    // And the byte never reaches a directory entry.
    for windows in [false, true] {
        assert_eq!(
            crate::disk::sanitize_filename_for(&d.name, windows),
            "foo_bar.mkv"
        );
    }

    // Only the spec's own TRAILING padding is trimmed, which is what
    // makes the two cases distinguishable at all.
    let mut padded = desc[..48 + 8].to_vec();
    padded.extend_from_slice(b"tail.mkv\0\0\0\0");
    assert_eq!(parse_filedesc(&padded).unwrap().1.name, "tail.mkv");
}

/// The two rows compose: a verify-only member's name can itself come
/// from a Unicode Filename packet.
#[test]
fn a_unicode_name_reaches_a_nonrecovery_member_too() {
    let set_id = [16u8; 16];
    let rec = [7u8; 16];
    let non = [8u8; 16];
    let mut buf = pkt(set_id, TYPE_MAIN, &main_ids_nonrec(4, &[rec], &[non]));
    buf.extend(pkt(set_id, TYPE_FILEDESC, &desc_body(rec, 1, 1, "a.bin")));
    buf.extend(pkt(
        set_id,
        TYPE_FILEDESC,
        &desc_body(non, 2, 1, "Notes.nfo"),
    ));
    buf.extend(pkt(
        set_id,
        TYPE_UNIFILEN,
        &uni_body(non, "Notés.nfo", true, false),
    ));
    let set = Par2Set::parse(&[&buf]).unwrap();
    assert_eq!(set.files[0].name, "a.bin");
    assert_eq!(set.nonrecovery[0].name, "Notés.nfo");
}
fn main_of(bs: u64, fids: &[[u8; 16]]) -> Vec<u8> {
    let mut b = bs.to_le_bytes().to_vec();
    b.extend_from_slice(&(fids.len() as u32).to_le_bytes());
    for f in fids {
        b.extend_from_slice(f);
    }
    b
}

/// M4-37. A four-block file whose IFSC lists FIVE entries is fully
/// described by the first four: the surplus entry describes a block
/// the file does not have. Dropping the whole packet over it costs
/// every block's evidence, so one flipped byte prices the file
/// WHOLLY missing and a repair that needed one recovery block needs
/// four.
#[test]
fn a_long_ifsc_keeps_the_blocks_the_file_actually_has() {
    const BS: usize = 4096;
    let data: Vec<u8> = (0..4u32 * BS as u32).map(|i| (i % 251) as u8).collect();
    let fid = honest_fid("data.bin", &data);
    let set_id = [7u8; 16];

    let mut buf = pkt(set_id, TYPE_MAIN, &main_of(BS as u64, &[fid]));
    buf.extend(pkt(set_id, TYPE_FILEDESC, &desc_of(fid, "data.bin", &data)));
    buf.extend(pkt(set_id, TYPE_IFSC, &ifsc_body(fid, &data, BS, 5)));

    let set = Par2Set::parse(&[&buf]).unwrap();
    let f = &set.files[0];
    assert_eq!(f.blocks.len(), 4, "the grid must cover the file exactly");
    let v = verify_file(f, BS as u64, &data);
    assert!(
        v.blocks.iter().all(|&ok| ok),
        "the four kept checks must be the file's own"
    );

    // One flipped byte in block 2 is ONE bad block, not four.
    let mut hurt = data.clone();
    hurt[2 * BS + 9] ^= 0xff;
    let v = verify_file(f, BS as u64, &hurt);
    assert_eq!(v.blocks.iter().filter(|ok| !**ok).count(), 1);
}

/// M4-37, the other half. A THREE-entry IFSC does not describe block
/// 3, and that block must never read as proven - the hazard
/// `short_ifsc_is_dropped_not_trusted` was written for. But the three
/// entries it does carry are the file's own, and throwing them away
/// is what makes a one-block flip cost four recovery blocks.
#[test]
fn a_short_ifsc_keeps_its_prefix_and_proves_nothing_past_it() {
    const BS: usize = 4096;
    let data: Vec<u8> = (0..4u32 * BS as u32).map(|i| (i % 241) as u8).collect();
    let fid = honest_fid("data.bin", &data);
    let set_id = [7u8; 16];

    let mut buf = pkt(set_id, TYPE_MAIN, &main_of(BS as u64, &[fid]));
    buf.extend(pkt(set_id, TYPE_FILEDESC, &desc_of(fid, "data.bin", &data)));
    buf.extend(pkt(set_id, TYPE_IFSC, &ifsc_body(fid, &data, BS, 3)));

    let set = Par2Set::parse(&[&buf]).unwrap();
    let f = &set.files[0];
    assert_eq!(f.blocks.len(), 4, "the grid still spans the whole file");
    assert!(
        f.blocks[..3].iter().all(|b| b.is_proven()),
        "the three entries the packet carried are evidence"
    );
    assert!(
        !f.blocks[3].is_proven(),
        "block 3 has no check and must not be provable"
    );

    // Over the file's OWN bytes the WHOLE-FILE MD5 settles it, block
    // 3 included: that digest covers every byte of every block, so a
    // file that hashes to the descriptor has a proven tail whatever
    // the block grid can express about it (M4-69). This assertion
    // read `[true, true, true, false]` for the hours between the two
    // lanes landing, on the reasoning that an unproven entry must
    // never vouch for an unposted tail - which is right about the
    // ENTRY and was being asked of the wrong evidence. It is also
    // what `par2repair`'s verify pass has always answered
    // (`Pass1Out::clean`), so the three halves now read one set one
    // way.
    let v = verify_file(f, BS as u64, &data);
    assert!(v.md5_ok, "the whole-file MD5 still covers every byte");
    assert_eq!(v.blocks, vec![true, true, true, true]);

    // AND THIS IS WHERE THE SHORT LIST IS HELD, which is why nothing
    // was lost above: with the whole-file MD5 FAILING there is no
    // evidence but the grid, and the unproven block stays false - a
    // flip inside the covered prefix is found by the prefix, and the
    // uncovered tail is still not vouched for by anything.
    let mut hurt = data.clone();
    hurt[BS + 5] ^= 0xff;
    let v = verify_file(f, BS as u64, &hurt);
    assert!(!v.md5_ok);
    assert_eq!(v.blocks, vec![true, false, true, false]);
}

/// M4-37's bound, and it is a bound on PADDING alone. `want` comes
/// off the wire (a declared length over a declared block size), so
/// filling a grid out to it must not let a 100-byte packet ask for a
/// terabyte of cells; past the ceiling such a packet is dropped
/// exactly as before. A packet that CARRIES its cells is bounded by
/// the input and keeps them however many there are - which
/// `a_four_byte_block_size_is_bounded_by_the_ifsc_it_must_carry`
/// pins from the other side, at 262144.
#[test]
fn a_wire_block_count_past_the_slice_limit_is_not_padded_to() {
    const BS: u64 = 4;
    let fid = [3u8; 16];
    let set_id = [7u8; 16];
    // 4 bytes per block, so this declares 2^40 blocks.
    let mut desc = fid.to_vec();
    desc.extend_from_slice(&[1u8; 16]);
    desc.extend_from_slice(&[2u8; 16]);
    desc.extend_from_slice(&(4u64 << 40).to_le_bytes());
    desc.extend_from_slice(b"huge.bin");
    let mut ifsc = fid.to_vec();
    ifsc.extend_from_slice(&[0u8; 20]);

    let mut buf = pkt(set_id, TYPE_MAIN, &main_of(BS, &[fid]));
    buf.extend(pkt(set_id, TYPE_FILEDESC, &desc));
    buf.extend(pkt(set_id, TYPE_IFSC, &ifsc));
    let set = Par2Set::parse(&[&buf]).unwrap();
    assert!(
        set.files[0].blocks.is_empty(),
        "an unbounded grid falls back to the whole-file MD5"
    );
}

/// M4-37's sharpest edge, and the one a placeholder made of zeros
/// invites: the guard on an [`BlockCheck::UNPROVEN`] slice is its
/// all-zero MD5, and the CRC-ONLY tiers never reach an MD5. Fast
/// verify claims a block on its CRC32 alone, and so do the
/// repairer's self-prove and pass-1 scans. Every u32 is somebody's
/// CRC32 and four appended bytes choose which, so a comparison
/// against the placeholder's zero FIELD is one a crafted block walks
/// straight past - `[157, 10, 217, 109]` is four bytes that hash to
/// exactly it. [`BlockCheck::crc_matches`] is what refuses it, and
/// every CRC-only site goes through that rather than the field.
#[test]
fn a_crafted_zero_crc_does_not_verify_an_unproven_slice() {
    const ZERO_CRC: [u8; 4] = [157, 10, 217, 109];
    assert_eq!(crc32fast::hash(&ZERO_CRC), 0, "the fixture is the point");
    assert_eq!(
        BlockCheck::UNPROVEN.crc32,
        0,
        "so a bare field comparison would have said yes"
    );
    assert!(!BlockCheck::UNPROVEN.crc_matches(0));
    assert!(!crate::live::check_block_crc(
        &BlockCheck::UNPROVEN,
        ZERO_CRC.len(),
        &ZERO_CRC
    ));
    // A real check with the same CRC value still answers for it -
    // the guard is the MD5 field, not the number.
    let real = BlockCheck {
        md5: [3u8; 16],
        crc32: 0,
    };
    assert!(real.crc_matches(0));
    assert!(!real.crc_matches(1));
    assert!(crate::live::check_block_crc(
        &real,
        ZERO_CRC.len(),
        &ZERO_CRC
    ));
}

/// M4-38. A file id is not an opaque label: the spec fixes it as the
/// MD5 of the descriptor's own hash16k, length and name, so a
/// descriptor either binds its own id or it does not. A packet that
/// COPIED another file's id must not out-race the real descriptor for
/// that id and hand its IFSC and Main slot to the wrong name and
/// MD5s.
#[test]
fn a_forged_file_id_never_beats_the_descriptor_that_binds_it() {
    const BS: usize = 4096;
    let real: Vec<u8> = (0..2u32 * BS as u32).map(|i| (i % 253) as u8).collect();
    let fid = honest_fid("real.bin", &real);
    let set_id = [7u8; 16];

    // The forgery: a different name, length and MD5s, wearing
    // `real.bin`'s id.
    let evil = vec![0xABu8; 64];
    let forged = desc_of(fid, "evil.bin", &evil);
    let honest = desc_of(fid, "real.bin", &real);

    for forged_first in [false, true] {
        let mut buf = pkt(set_id, TYPE_MAIN, &main_of(BS as u64, &[fid]));
        let (a, b) = if forged_first {
            (&forged, &honest)
        } else {
            (&honest, &forged)
        };
        buf.extend(pkt(set_id, TYPE_FILEDESC, a));
        buf.extend(pkt(set_id, TYPE_FILEDESC, b));
        buf.extend(pkt(set_id, TYPE_IFSC, &ifsc_body(fid, &real, BS, 2)));

        let set = Par2Set::parse(&[&buf]).unwrap();
        assert_eq!(set.files.len(), 1);
        assert_eq!(
            set.files[0].name, "real.bin",
            "forged_first={forged_first}: arrival order must not pick the name"
        );
        assert_eq!(set.files[0].length, real.len() as u64);
        assert_eq!(set.files[0].md5, <[u8; 16]>::from(Md5::digest(&real)));
    }
}

/// M4-38 must not become a refusal. Every FileDesc packet in this
/// repository's fixtures binds its own id (18 of 18, measured 30 Aug
/// 2026), but nothing in the format makes a producer's id
/// verifiable by any other tool - par2cmdline never recomputes it -
/// so a set whose ids simply follow a different rule still has to
/// parse. An unbound id is only ever OUT-RANKED, never dropped.
#[test]
fn an_unbound_file_id_still_describes_its_file() {
    const BS: usize = 4096;
    let data: Vec<u8> = (0..2u32 * BS as u32).map(|i| (i % 239) as u8).collect();
    let fid = [0x5Au8; 16]; // binds nothing
    let set_id = [7u8; 16];

    let mut buf = pkt(set_id, TYPE_MAIN, &main_of(BS as u64, &[fid]));
    buf.extend(pkt(set_id, TYPE_FILEDESC, &desc_of(fid, "odd.bin", &data)));
    buf.extend(pkt(set_id, TYPE_IFSC, &ifsc_body(fid, &data, BS, 2)));

    let set = Par2Set::parse(&[&buf]).unwrap();
    assert_eq!(set.files.len(), 1, "an unbound id is not a refusal");
    assert_eq!(set.files[0].name, "odd.bin");
    assert_eq!(set.files[0].blocks.len(), 2);
}

// -- NZBFAST_VERIFY_IFSC_ONLY: the experimental verdict tier --------
//
// The knob is default off and changes what "verified" MEANS, so the
// whole of its licence to exist is this differential: for every set
// and every damage shape below, the two tiers must reach the SAME
// FileVerify - except on the one spec-legal shape that is proved
// undetectable here and pinned by name.

/// Scratch path for a fixture, unique per process and call so the
/// suite stays safe under nextest's process-per-test and under
/// `cargo test`'s one process for the whole crate.
fn scratch_path(tag: &str) -> std::path::PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "nzbkit-par2-ifsc-only-{tag}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
    ))
}

/// Run one fixture through BOTH verdict tiers and require the same
/// answer in all three fields. Returns that answer.
fn assert_tiers_agree(file: &Par2File, block_size: u64, bytes: &[u8], case: &str) -> FileVerify {
    let path = scratch_path("agree");
    std::fs::write(&path, bytes).expect("write IFSC-only fixture");
    // Both thread hints, because the tier declines into
    // `verify_blocks_path_or_streaming`, whose serial and positioned
    // halves are chosen by exactly this number.
    let mut answer = None;
    for threads in [1usize, 8] {
        let off = verify_file_path_tiered(&path, file, block_size, threads, false)
            .expect("a regular fixture file cannot fail to read");
        let on = verify_file_path_tiered(&path, file, block_size, threads, true)
            .expect("a regular fixture file cannot fail to read");
        assert_eq!(off.blocks, on.blocks, "{case} (threads {threads}): blocks");
        assert_eq!(off.md5_ok, on.md5_ok, "{case} (threads {threads}): md5_ok");
        assert_eq!(
            off.md5_16k_ok, on.md5_16k_ok,
            "{case} (threads {threads}): md5_16k_ok"
        );
        answer = Some(off);
    }
    let _ = std::fs::remove_file(path);
    answer.expect("both thread hints ran")
}

/// Deterministic xorshift, so a failure is reproducible from the
/// case index alone and the suite never depends on the clock.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// THE DIFFERENTIAL. Random honest sets, random damage, both tiers.
///
/// The lengths straddle `VERIFY_PAR_MIN_BYTES` (64 KiB in a test
/// build) so the positioned pool, the pipelined one-pass reader and
/// the serial streamer all answer somewhere in the sweep, and the
/// block sizes are deliberately not divisors of the lengths so the
/// zero-padded final slice is exercised on nearly every case.
#[test]
fn the_ifsc_only_tier_matches_the_default_tier_over_random_damage() {
    let mut rng = Rng(0x9E3779B97F4A7C15);
    for case in 0..96u32 {
        let bs = [1024usize, 4096, 16 << 10, 64 << 10][rng.below(4)];
        let len = bs * (1 + rng.below(24)) + rng.below(bs.min(4096) + 1);
        let mut data: Vec<u8> = (0..len)
            .map(|i| (i as u8) ^ ((i >> 8) as u8).wrapping_mul(37) ^ case as u8)
            .collect();
        let file = synth_file(&data, bs);
        match rng.below(6) {
            // Clean: the case the knob exists for.
            0 | 1 => {}
            // One flipped bit, somewhere.
            2 => {
                let at = rng.below(len);
                data[at] ^= 1 << rng.below(8);
            }
            // A whole slice replaced, so a lane's range is all bad.
            3 => {
                let block = rng.below(len.div_ceil(bs));
                let start = block * bs;
                let end = (start + bs).min(len);
                for (k, byte) in data[start..end].iter_mut().enumerate() {
                    *byte = (k as u8).wrapping_mul(97).wrapping_add(11);
                }
            }
            // Short on disk: the size-mismatch shortcut.
            4 => {
                let keep = rng.below(len);
                data.truncate(keep);
            }
            // Long on disk: also a size mismatch, other side.
            _ => {
                let extra = 1 + rng.below(bs * 2);
                data.extend((0..extra).map(|i| (i as u8).wrapping_mul(31)));
            }
        }
        assert_tiers_agree(&file, bs as u64, &data, &format!("case {case}"));
    }
}

/// The shapes the tier must DECLINE, each for its own reason, and on
/// which it therefore answers exactly as the default tier does.
#[test]
fn the_ifsc_only_tier_declines_every_grid_that_does_not_cover_the_file() {
    const BS: usize = 4096;
    let len = (128 << 10) + 517;
    let data: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(53)).collect();

    // A zero-length member: "every block proved" is vacuously true
    // over no bytes at all, which is the one claim this must never
    // make. Its grid is empty, so the tier declines on the length.
    let empty = synth_file(&[], BS);
    assert_eq!(empty.blocks.len(), 0);
    let got = assert_tiers_agree(&empty, BS as u64, &[], "zero-length member");
    assert!(got.md5_ok, "an empty member still verifies the old way");

    // A short IFSC fitted out with UNPROVEN cells: the suffix covers
    // nothing, so only the whole-file digest can settle those bytes.
    let mut short = synth_file(&data, BS);
    short.blocks[3..].fill(BlockCheck::UNPROVEN);
    let got = assert_tiers_agree(&short, BS as u64, &data, "short IFSC, clean payload");
    assert!(got.md5_ok, "the whole-file digest still settles it");

    // An INTERIOR unproven cell, which no truncation produces and
    // only a crafted set carries. Same rule, reached from the middle.
    let mut interior = synth_file(&data, BS);
    interior.blocks[5] = BlockCheck::UNPROVEN;
    let got = assert_tiers_agree(&interior, BS as u64, &data, "interior UNPROVEN cell");
    assert!(got.md5_ok);

    // No IFSC at all (`fit_ifsc` refuses to pad this far, or the set
    // simply carries none).
    let mut none = synth_file(&data, BS);
    none.blocks.clear();
    assert_tiers_agree(&none, BS as u64, &data, "no IFSC");

    // A grid whose length disagrees with the declared size. Nothing
    // well-formed reaches this, and the tier must not read a
    // truncated grid as covering the tail.
    let mut trimmed = synth_file(&data, BS);
    trimmed.blocks.truncate(trimmed.blocks.len() - 1);
    assert_tiers_agree(&trimmed, BS as u64, &data, "grid shorter than the file");
}

/// H7's MIRROR: the bytes on disk carry the FileDesc whole-file MD5
/// and the IFSC beside it describes a DIFFERENT payload. The default
/// tier calls that clean, because the FileDesc digest arbitrates
/// (`verify_file`'s contract). The IFSC-only tier sees failing
/// blocks - and MUST decline rather than report damage, which is why
/// `ifsc_only_attempt` returns `Some` for a clean verdict only.
#[test]
fn the_ifsc_only_tier_declines_when_the_ifsc_denies_bytes_the_filedesc_proves() {
    const BS: usize = 4096;
    let len = (128 << 10) + 91;
    let real: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(101)).collect();
    let other: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(103)).collect();
    let desc = synth_file(&real, BS);
    let ifsc = synth_file(&other, BS);
    let meta = Par2File {
        blocks: ifsc.blocks,
        ..desc
    };
    let got = assert_tiers_agree(&meta, BS as u64, &real, "H7 mirror");
    assert!(got.md5_ok, "the FileDesc digest still arbitrates");
    assert!(
        got.blocks.iter().all(|&ok| ok),
        "and settles every block it covers"
    );
}

/// THE ONE SHAPE THE TWO TIERS DISAGREE ON, pinned honestly.
///
/// Nothing in PAR2 binds an IFSC packet to the FileDesc beside it -
/// the file id hashes hash16k, length and name, never the whole-file
/// MD5 - so a spec-legal set can pair file A's descriptor with file
/// B's IFSC. With bytes B on disk, every block proves and the
/// FileDesc digest fails. This is H7 (08-08 sweep), and it is
/// UNDETECTABLE by a tier that does not compute the whole-file
/// digest, so there is no fallback to write: the honest thing is to
/// pin the divergence and put the policy question to a human.
///
/// Both halves matter. The 16 KiB head check refuses the pairing a
/// random or accidental set produces, so the tiers still agree
/// there; a pairing built with a SHARED first 16 KiB - which is what
/// a well-formed set needs anyway, since both packets must carry the
/// same file id - walks past it, and that is the divergence.
#[test]
fn the_ifsc_only_tier_diverges_only_on_the_h7_shape() {
    const BS: usize = 4096;
    let len = (128 << 10) + 33;
    assert!(len > HASH16K_LEN, "the head check must be reachable");

    // (a) The naive pairing: the two payloads differ from byte 0, so
    // hash16k separates them and the tier declines.
    let a: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(11)).collect();
    let b: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(13)).collect();
    let naive = Par2File {
        blocks: synth_file(&b, BS).blocks,
        ..synth_file(&a, BS)
    };
    let got = assert_tiers_agree(&naive, BS as u64, &b, "H7 with differing heads");
    assert!(!got.md5_ok, "the FileDesc digest denies these bytes");

    // (b) The pairing a real set would have to use: A and B share a
    // name, a length AND a first 16 KiB, so both packets compute the
    // same file id and the head check cannot separate them.
    let mut c = a.clone();
    for (i, byte) in c[HASH16K_LEN..].iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(17).wrapping_add(5);
    }
    assert_eq!(a[..HASH16K_LEN], c[..HASH16K_LEN]);
    assert_ne!(a, c);
    let crafted = Par2File {
        blocks: synth_file(&c, BS).blocks,
        ..synth_file(&a, BS)
    };

    let path = scratch_path("h7");
    std::fs::write(&path, &c).expect("write H7 fixture");
    let off = verify_file_path_tiered(&path, &crafted, BS as u64, 8, false).unwrap();
    let on = verify_file_path_tiered(&path, &crafted, BS as u64, 8, true).unwrap();
    let _ = std::fs::remove_file(path);

    assert!(
        !off.md5_ok,
        "knob off: the FileDesc whole-file MD5 is the verdict, and it fails"
    );
    assert!(
        off.blocks.iter().all(|&ok| ok),
        "knob off: every IFSC block still matches - that is the contradiction"
    );
    assert!(
        on.md5_ok,
        "knob on: the IFSC is the verdict, and it passes - THE divergence, \
             and the whole of the policy question"
    );
    assert!(on.md5_16k_ok, "both packets agree about the head");
}

// -- The ONE value: which surface wins ------------------------------
//
// `nzbfast verify --fast`, the daemon's `fast_final_check` setting
// and NZBFAST_VERIFY_IFSC_ONLY all resolve HERE, and section 21 of
// research/PAR2-PERF-AUDIT-2026-09-02.md makes that load-bearing:
// letting the CLI and the daemon answer under different rules is
// worse than either rule alone. These tests are the pin.
//
// They share one process-global, so they are ONE test: two of them
// would race under `cargo test`'s single process for the crate, and
// the trap is documented in CONTRIBUTING.md's build section.

#[test]
fn the_fast_check_surfaces_resolve_to_one_value() {
    // The global starts unset, so the answer is the environment's -
    // and the suite runs with the variable unset, so it is off. This
    // is also the KEEP RULE: with nothing set, behaviour is today's.
    clear_fast_check();
    assert!(
        !fast_check_enabled(),
        "default off: no surface has spoken and the variable is unset"
    );

    // An explicit choice from any surface beats that default, in
    // BOTH directions - a surface saying off has to be told apart
    // from a surface saying nothing, or a setting could never turn
    // off what the environment turned on.
    set_fast_check(true);
    assert!(fast_check_enabled(), "an explicit yes is honoured");
    set_fast_check(false);
    assert!(
        !fast_check_enabled(),
        "an explicit no is honoured, and is NOT the same state as unset"
    );

    // Last writer wins, which is what makes the precedence work at
    // the call sites: the daemon restores the saved setting at
    // startup and `apply_setting` overwrites it live, and the CLI
    // writes its flag once before anything reads it.
    set_fast_check(true);
    assert!(
        fast_check_enabled(),
        "a later choice replaces an earlier one"
    );

    // Leave the process as this test found it. Every other test in
    // this crate resolves through the same global.
    clear_fast_check();
    assert!(!fast_check_enabled(), "restored to the default");
}

// ---- the two optional Text ("comment") packets ------------------------

/// A minimal one-member set, so each comment case below is one packet
/// of difference and nothing else.
fn commented(set_id: [u8; 16], extra: &[(&[u8; 16], Vec<u8>)]) -> Par2Set {
    let fid = [9u8; 16];
    let mut buf = pkt(set_id, TYPE_MAIN, &main_ids(4, &[fid]));
    buf.extend(pkt(set_id, TYPE_FILEDESC, &desc_body(fid, 1, 1, "a.bin")));
    for (ptype, body) in extra {
        assert!(
            body.len().is_multiple_of(4),
            "fixture body must survive the packet scanner"
        );
        buf.extend(pkt(set_id, ptype, body));
    }
    Par2Set::parse(&[&buf]).unwrap()
}

fn ascii_body(text: &str) -> Vec<u8> {
    let mut b = text.as_bytes().to_vec();
    while !b.len().is_multiple_of(4) {
        b.push(0);
    }
    b
}

/// The Unicode TEXT packet's 16-byte MD5 cross-reference, then UTF-16LE.
/// Named apart from `uni_body` above, which builds a Unicode FILENAME
/// packet - a different packet with a different leading field.
fn comm_uni_body(md5: [u8; 16], text: &str) -> Vec<u8> {
    let mut b = md5.to_vec();
    for u in text.encode_utf16() {
        b.extend_from_slice(&u.to_le_bytes());
    }
    while !b.len().is_multiple_of(4) {
        b.push(0);
    }
    b
}

#[test]
fn either_text_packet_alone_gives_the_set_its_comment() {
    assert_eq!(
        commented([1u8; 16], &[(TYPE_COMMASCI, ascii_body("posted by hand"))]).comment,
        Some("posted by hand".to_string())
    );
    assert_eq!(
        commented(
            [2u8; 16],
            &[(TYPE_COMMUNI, comm_uni_body([0; 16], "日本語 comment"))]
        )
        .comment,
        Some("日本語 comment".to_string())
    );
    assert_eq!(commented([3u8; 16], &[]).comment, None);
}

/// The Unicode spelling outranks the ASCII one where a producer wrote
/// both, for the Unicode FILENAME packet's reason: the ASCII copy is
/// the lossy half by construction, written for readers that understand
/// nothing else.
#[test]
fn the_unicode_comment_outranks_the_ascii_one() {
    let set = commented(
        [4u8; 16],
        &[
            (TYPE_COMMASCI, ascii_body("Bjork - Vespertine")),
            (TYPE_COMMUNI, comm_uni_body([7; 16], "Björk - Vespertine")),
        ],
    );
    assert_eq!(set.comment.as_deref(), Some("Björk - Vespertine"));
}

/// The MD5 cross-reference is READ PAST and never checked: a Unicode
/// packet naming an ASCII packet this set does not carry still yields
/// its comment. Checking it would make one optional packet's survival a
/// precondition for the other's.
#[test]
fn a_unicode_comment_stands_without_the_ascii_packet_it_names() {
    let set = commented(
        [5u8; 16],
        &[(TYPE_COMMUNI, comm_uni_body([0xAB; 16], "alone"))],
    );
    assert_eq!(set.comment.as_deref(), Some("alone"));
}

/// Two packets of the SAME type carrying DIFFERENT comments annihilate,
/// the way every other claim in this parse does (W4-10) - the same
/// answer in every packet order, rather than a race the scan order
/// decides. Two packets of DIFFERENT types are not a contradiction at
/// all, which is the whole reason they are claimed apart.
#[test]
fn two_disagreeing_comments_of_one_type_annihilate() {
    assert_eq!(
        commented(
            [6u8; 16],
            &[
                (TYPE_COMMASCI, ascii_body("one thing")),
                (TYPE_COMMASCI, ascii_body("another thing")),
            ],
        )
        .comment,
        None
    );
    // The ASCII half losing itself does not take the Unicode half down.
    assert_eq!(
        commented(
            [7u8; 16],
            &[
                (TYPE_COMMASCI, ascii_body("one thing")),
                (TYPE_COMMASCI, ascii_body("another thing")),
                (TYPE_COMMUNI, comm_uni_body([0; 16], "the survivor")),
            ],
        )
        .comment
        .as_deref(),
        Some("the survivor")
    );
    // And a repeat of the SAME comment is not a contradiction: comment
    // packets ride in every volume, so a multi-file parse sees each
    // of them once per file before the packet-MD5 dedupe even applies.
    assert_eq!(
        commented(
            [8u8; 16],
            &[
                (TYPE_COMMASCI, ascii_body("said twice")),
                (TYPE_COMMASCI, ascii_body("said twice")),
            ],
        )
        .comment
        .as_deref(),
        Some("said twice")
    );
}

/// A control character is refused rather than stripped, and the set is
/// otherwise untouched. The comment is the one field of a PAR2 set an
/// attacker chooses freely and that lands in front of a human
/// unaltered, and an ESC in a terminal is an escape sequence; the
/// refusal costs exactly the comment, because a comment keys nothing.
///
/// EVERY BODY HERE IS 4-ALIGNED, for `an_undecodable_unicode_filename_
/// packet_leaves_the_filedesc_name`'s reason: a body that is not would
/// never reach the parser, and the case would assert the SCANNER's rule
/// while claiming to be about this one.
#[test]
fn a_comment_carrying_a_control_character_is_refused_outright() {
    for body in [
        ascii_body("wipe \u{1b}[2J screen"),
        ascii_body("bell \u{7} here"),
        ascii_body("nul \u{0} here"),
        ascii_body(""),
    ] {
        let set = commented([10u8; 16], &[(TYPE_COMMASCI, body)]);
        assert_eq!(set.comment, None);
        assert_eq!(set.files.len(), 1, "the member is untouched");
    }
    for body in [
        comm_uni_body([0; 16], "wipe \u{1b}[2J screen"),
        comm_uni_body([0; 16], ""),
    ] {
        assert_eq!(commented([11u8; 16], &[(TYPE_COMMUNI, body)]).comment, None);
    }
    // Newline, carriage return and tab are what make a comment a
    // comment and are kept.
    assert_eq!(
        commented(
            [12u8; 16],
            &[(TYPE_COMMASCI, ascii_body("line one\r\nline two\tindented"))]
        )
        .comment
        .as_deref(),
        Some("line one\r\nline two\tindented")
    );
}

/// Bytes that are not UTF-8 are refused rather than lossily mapped -
/// `parse_unifilen`'s rule, for its reason: the packet is OPTIONAL, so
/// refusing it leaves the set exactly as usable as if it had never been
/// written, and that is what buys the strict side.
#[test]
fn a_text_packet_that_does_not_decode_is_refused() {
    assert_eq!(
        commented([13u8; 16], &[(TYPE_COMMASCI, vec![0xFF, 0xFE, 0xFD, b'a'])]).comment,
        None
    );
    // An unpaired high surrogate in the Unicode packet.
    let mut body = [0u8; 16].to_vec();
    body.extend_from_slice(&[0x00, 0xD8, b'a', 0]);
    assert_eq!(commented([14u8; 16], &[(TYPE_COMMUNI, body)]).comment, None);
}
