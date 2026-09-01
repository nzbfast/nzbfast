//! PAR2 parser tests against real par2cmdline 1.2.0 output.
//! Fixture provenance: tests/fixtures/par2/README.txt
//! (`par2 create -s4096 -r34 -n1 -a testset alpha.bin beta.bin`)

use nzbkit::par2::{Par2Set, verify_file, verify_file_blocks, verify_file_streaming};

const MAIN: &[u8] = include_bytes!("../fixtures/par2/testset.par2");
const VOL: &[u8] = include_bytes!("../fixtures/par2/testset.vol0+4.par2");
const ALPHA: &[u8] = include_bytes!("../fixtures/par2/alpha.bin"); // 10 KiB
const BETA: &[u8] = include_bytes!("../fixtures/par2/beta.bin"); // 33 KiB

fn parse_set() -> Par2Set {
    Par2Set::parse(&[MAIN, VOL]).expect("fixture set parses")
}

fn file<'a>(set: &'a Par2Set, name: &str) -> &'a nzbkit::par2::Par2File {
    set.files
        .iter()
        .find(|f| f.name == name)
        .unwrap_or_else(|| panic!("file {name} present"))
}

#[test]
fn parses_fixture_set_metadata() {
    let set = parse_set();
    assert_eq!(set.block_size, 4096);
    assert_eq!(set.files.len(), 2);
    // testset.vol0+4.par2 carries 4 recovery slices - the "+4". This is
    // the field `get::settle` seeds `on_hand` from, and since Y4b it
    // counts only slices that can SERVE a block rather than every
    // exponent the volume mentions.
    assert_eq!(set.recovery_blocks_seen, 4);

    let alpha = file(&set, "alpha.bin");
    assert_eq!(alpha.length, 10240);
    assert_eq!(alpha.blocks.len(), 3); // ceil(10240/4096)
    let beta = file(&set, "beta.bin");
    assert_eq!(beta.length, 33792);
    assert_eq!(beta.blocks.len(), 9); // ceil(33792/4096)

    // par2cmdline sorts the recovery set by file id; the Main packet order is
    // what we expose. For this fixture beta.bin sorts first.
    assert_eq!(set.files[0].name, "beta.bin");
    assert_eq!(set.files[1].name, "alpha.bin");
}

#[test]
fn main_par2_alone_parses_without_recovery_blocks() {
    let set = Par2Set::parse(&[MAIN]).expect("index alone parses");
    assert_eq!(set.block_size, 4096);
    assert_eq!(set.files.len(), 2);
    assert_eq!(set.recovery_blocks_seen, 0);
}

#[test]
fn pristine_data_verifies_fully() {
    let set = parse_set();
    for (name, data) in [("alpha.bin", ALPHA), ("beta.bin", BETA)] {
        let f = file(&set, name);
        let blocks = verify_file_blocks(f, set.block_size, data);
        assert!(blocks.iter().all(|&ok| ok), "{name}: all blocks good");
        let v = verify_file(f, set.block_size, data);
        assert!(v.md5_ok, "{name}: whole-file MD5");
        assert!(v.md5_16k_ok, "{name}: MD5-16k");
    }
}

#[test]
fn corrupt_byte_flags_exactly_its_block() {
    let set = parse_set();
    let f = file(&set, "beta.bin");
    let mut data = BETA.to_vec();
    // Flip a byte in block 5 (offsets 5*4096 .. 6*4096).
    data[5 * 4096 + 123] ^= 0xff;
    let v = verify_file(f, set.block_size, &data);
    let expected: Vec<bool> = (0..9).map(|i| i != 5).collect();
    assert_eq!(v.blocks, expected, "only block 5 flagged");
    assert!(!v.md5_ok, "whole-file MD5 fails");
    // Corruption is past the first 16 KiB, so md5-16k still passes.
    assert!(v.md5_16k_ok);
}

#[test]
fn corrupt_last_padded_block_detected() {
    let set = parse_set();
    let f = file(&set, "beta.bin");
    let mut data = BETA.to_vec();
    let last = data.len() - 1; // inside the final, zero-padded block (index 8)
    data[last] ^= 0x01;
    let blocks = verify_file_blocks(f, set.block_size, &data);
    let expected: Vec<bool> = (0..9).map(|i| i != 8).collect();
    assert_eq!(blocks, expected);
}

#[test]
fn truncated_data_fails_missing_blocks() {
    let set = parse_set();
    let f = file(&set, "beta.bin");
    let v = verify_file(f, set.block_size, &BETA[..2 * 4096 + 100]);
    assert_eq!(v.blocks.len(), 9);
    assert!(v.blocks[0] && v.blocks[1]);
    assert!(v.blocks[2..].iter().all(|&ok| !ok));
    assert!(!v.md5_ok);
    // Only ~8 KiB present, so the first-16k hash fails too.
    assert!(!v.md5_16k_ok);
}

#[test]
fn corrupt_packet_skipped_and_recovered_via_duplicates() {
    let set_ref = parse_set();
    // Corrupt one byte inside the FIRST packet body of the main .par2 -
    // its packet MD5 no longer verifies, so the parser must skip it. The
    // volume file duplicates every critical packet, so the parse still
    // succeeds with identical metadata.
    let mut broken = MAIN.to_vec();
    broken[70] ^= 0xff; // inside first packet's body (header is 64 bytes)
    let set = Par2Set::parse(&[&broken, VOL]).expect("duplicates rescue the parse");
    assert_eq!(set.block_size, set_ref.block_size);
    assert_eq!(set.files.len(), set_ref.files.len());
    for (a, b) in set.files.iter().zip(set_ref.files.iter()) {
        assert_eq!(a.name, b.name);
        assert_eq!(a.length, b.length);
        assert_eq!(a.md5, b.md5);
        assert_eq!(a.blocks, b.blocks);
    }
    assert_eq!(set.recovery_blocks_seen, 4);
}

#[test]
fn corrupt_index_alone_degrades_gracefully() {
    // Same corruption, but with no volume to rescue it: parse either fails
    // with NoMainPacket (if the Main packet was hit) or succeeds partially.
    let mut broken = MAIN.to_vec();
    broken[70] ^= 0xff;
    match Par2Set::parse(&[&broken]) {
        Ok(set) => assert!(set.files.len() <= 2),
        Err(e) => assert_eq!(e, nzbkit::par2::Par2Error::NoMainPacket),
    }
}

#[test]
fn tolerates_leading_and_trailing_garbage() {
    let mut noisy = b"garbage garbage PAR2\0PK not-quite ".to_vec();
    noisy.extend_from_slice(MAIN);
    noisy.extend_from_slice(b"trailing junk PAR2\0PKT\x03\x00\x00");
    let set = Par2Set::parse(&[&noisy, VOL]).expect("garbage tolerated");
    assert_eq!(set.block_size, 4096);
    assert_eq!(set.files.len(), 2);
}

#[test]
fn duplicate_inputs_do_not_double_count() {
    // Feeding the same volume twice must not inflate recovery_blocks_seen.
    let set = Par2Set::parse(&[MAIN, VOL, VOL, MAIN]).expect("parses");
    assert_eq!(set.recovery_blocks_seen, 4);
    assert_eq!(set.files.len(), 2);
}

#[test]
fn short_file_md5_16k_is_unpadded_whole_file_md5() {
    // alpha.bin is 10 KiB < 16 KiB. par2cmdline 1.2.0 hashes only the bytes
    // that exist (min(len, 16384)) - NO zero-padding - so for a short file
    // md5_16k equals the whole-file md5. Verified against the FileDesc
    // packet in the fixture (see fixtures/par2/README.txt).
    let set = parse_set();
    let alpha = file(&set, "alpha.bin");
    assert_eq!(alpha.md5, alpha.md5_16k);
    let v = verify_file(alpha, set.block_size, ALPHA);
    assert!(v.md5_ok && v.md5_16k_ok);

    // And the padded interpretation would be WRONG:
    use md5::{Digest, Md5};
    let mut padded = ALPHA.to_vec();
    padded.resize(16384, 0);
    let padded_md5: [u8; 16] = Md5::digest(&padded).into();
    assert_ne!(padded_md5, alpha.md5_16k);
}

#[test]
fn no_main_packet_errors() {
    use nzbkit::par2::Par2Error;
    assert!(matches!(
        Par2Set::parse(&[b"not a par2 file at all".as_slice()]),
        Err(Par2Error::NoMainPacket)
    ));
    assert!(matches!(Par2Set::parse(&[]), Err(Par2Error::NoMainPacket)));
}

/// The repost fingerprint (Tier C item 5): the sidecar's per-member
/// hash16k, which describes the OUTER volumes and so survives RAR header
/// encryption. Short members are excluded on purpose - under 16 KiB the
/// field is just the whole-file MD5 of an nfo or a sample, which
/// collides across unrelated releases and would name a post after the
/// wrong film.
#[test]
fn member_hash16k_fingerprints_the_long_members_only() {
    let set = parse_set();
    let hashes = set.member_hash16k();
    // beta.bin is 33 KiB and qualifies; alpha.bin is 10 KiB and does not.
    assert_eq!(hashes.len(), 1, "got {hashes:?}");
    assert_eq!(hashes[0].1, "beta.bin");
    assert_eq!(
        hashes[0].0,
        nzbkit::par2::hex16(&file(&set, "beta.bin").md5_16k)
    );
    assert_eq!(hashes[0].0.len(), 32);
    assert!(
        hashes[0]
            .0
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
    // The fingerprint is the file's own bytes, so an independent hash of
    // the first 16 KiB has to agree with what the sidecar declared.
    let want: [u8; 16] = <md5::Md5 as md5::Digest>::digest(&BETA[..16384]).into();
    assert_eq!(hashes[0].0, nzbkit::par2::hex16(&want));
}

// --- streaming verification: differential against the buffered reference ---
//
// `verify_file` is the reference implementation (its own docs, and
// `verify_file_blocks`', say so). `verify_file_streaming` is what the settle
// path and `nzbfast verify` now run, because the buffered form needed a 30 GB
// set member resident to check it. A verification verdict is a safety
// contract, so the only acceptable difference between the two is memory: for
// every input below they must agree on all three fields.

/// A reader that hands back at most `max` bytes per call, and - when
/// `interrupt` is set - fails every other call with `Interrupted` first.
/// `Read` is allowed both behaviours and a file over a slow or signalled
/// mount does both; the buffered form never had to survive either.
struct Choked<'a> {
    data: &'a [u8],
    max: usize,
    interrupt: bool,
    calls: usize,
}

impl std::io::Read for Choked<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.calls += 1;
        if self.interrupt && self.calls % 2 == 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "eintr",
            ));
        }
        let n = buf.len().min(self.max).min(self.data.len());
        buf[..n].copy_from_slice(&self.data[..n]);
        self.data = &self.data[n..];
        Ok(n)
    }
}

/// Every read granularity, with and without spurious `Interrupted`s.
/// 4096 is the fixture's block size, so its neighbours put a block
/// boundary exactly on, just before and just after a read boundary.
fn assert_streaming_agrees(f: &nzbkit::par2::Par2File, block_size: u64, data: &[u8], case: &str) {
    let want = verify_file(f, block_size, data);
    for max in [1usize, 3, 4095, 4096, 4097, 16384, usize::MAX] {
        for interrupt in [false, true] {
            let got = verify_file_streaming(
                f,
                block_size,
                Choked {
                    data,
                    max,
                    interrupt,
                    calls: 0,
                },
            )
            .unwrap_or_else(|e| panic!("{case} (max {max}): {e}"));
            let where_ = format!("{case} (reads of {max}, eintr {interrupt})");
            assert_eq!(want.blocks, got.blocks, "{where_}: per-block flags");
            assert_eq!(want.md5_ok, got.md5_ok, "{where_}: whole-file MD5");
            assert_eq!(want.md5_16k_ok, got.md5_16k_ok, "{where_}: MD5-16k");
        }
    }
}

#[test]
fn streaming_verify_matches_reference_on_the_fixtures() {
    let set = parse_set();
    let alpha = file(&set, "alpha.bin"); // 10 KiB: under 16k, short last block
    let beta = file(&set, "beta.bin"); // 33 KiB: 8 whole blocks plus 1024

    // Clean, and the short-file case where md5_16k is the whole-file MD5.
    assert_streaming_agrees(alpha, set.block_size, ALPHA, "alpha pristine");
    assert_streaming_agrees(beta, set.block_size, BETA, "beta pristine");
    // Vacuous agreement would be all-false on both sides; these are not.
    assert!(verify_file(beta, set.block_size, BETA).md5_ok);

    // Corruption: inside a whole block, inside the zero-padded final block,
    // and inside the first 16 KiB (which fails md5_16k as well).
    for (off, case) in [
        (5 * 4096 + 123, "beta mid-block flip"),
        (BETA.len() - 1, "beta padded-tail flip"),
        (7usize, "beta head flip"),
    ] {
        let mut hurt = BETA.to_vec();
        hurt[off] ^= 0xff;
        assert_streaming_agrees(beta, set.block_size, &hurt, case);
    }

    // Short input: mid-block, on a block boundary, and nothing at all.
    assert_streaming_agrees(
        beta,
        set.block_size,
        &BETA[..2 * 4096 + 100],
        "beta truncated",
    );
    assert_streaming_agrees(
        beta,
        set.block_size,
        &BETA[..4 * 4096],
        "beta cut on a boundary",
    );
    assert_streaming_agrees(beta, set.block_size, &[], "beta empty");
    assert_streaming_agrees(alpha, set.block_size, &[], "alpha empty");

    // Trailing bytes past the last expected block create no extra flags.
    let mut longer = BETA.to_vec();
    longer.extend_from_slice(&[0xa5; 9000]);
    assert_streaming_agrees(beta, set.block_size, &longer, "beta with trailing bytes");

    // A block size that is not the set's, and the degenerate zero - both
    // reference behaviours, neither of them a panic.
    assert_streaming_agrees(beta, 4092, BETA, "beta at the wrong block size");
    assert_streaming_agrees(beta, 0, BETA, "beta at block size zero");
}

/// Build one structurally valid PAR2 packet, sealed with the packet MD5
/// the scanner checks (MD5 of set id + type + body).
fn pkt(set_id: [u8; 16], ptype: &[u8; 16], body: &[u8]) -> Vec<u8> {
    use md5::Digest as _;
    assert!(
        body.len().is_multiple_of(4),
        "packet bodies are 4-byte aligned"
    );
    let mut p = Vec::new();
    p.extend_from_slice(b"PAR2\0PKT");
    p.extend_from_slice(&(64u64 + body.len() as u64).to_le_bytes());
    p.extend_from_slice(&[0u8; 16]); // md5, patched below
    p.extend_from_slice(&set_id);
    p.extend_from_slice(ptype);
    p.extend_from_slice(body);
    let d: [u8; 16] = md5::Md5::digest(&p[32..]).into();
    p[16..32].copy_from_slice(&d);
    p
}

/// X5-14, against the REAL par2cmdline set rather than a synthetic one.
///
/// One physical `.par2` whose FIRST valid packet belongs to another set
/// and whose remainder is this whole fixture. `set_id_of` returned that
/// first packet's id, so a caller grouping physical files by it filed
/// the buffer under the foreign set; reparsing that group then saw the
/// fixture's packets and answered `MixedRecoverySets`, and no group for
/// the real set was ever formed - a complete, valid, two-file set
/// vanished on the strength of one 84-byte Creator packet.
///
/// The synthetic arms of this row live in `par2::tests`; what this one
/// adds is that a real set with real IFSC lists survives contamination
/// INTACT - every file, its length and its per-block checksums - rather
/// than merely parsing.
#[test]
fn a_stray_foreign_packet_does_not_hide_the_real_set_behind_it() {
    let clean = parse_set();
    let foreign = [0xA5u8; 16];
    assert_ne!(foreign, clean.recovery_set_id, "the stray set is foreign");

    let mut buf = pkt(foreign, b"PAR 2.0\0Creator\0", b"someone-else\0\0\0\0");
    buf.extend_from_slice(MAIN);
    buf.extend_from_slice(VOL);

    assert_eq!(
        Par2Set::set_id_of(&buf),
        Some(clean.recovery_set_id),
        "the grouping key followed one stray packet instead of the set"
    );
    let got = Par2Set::parse(&[&buf]).expect("the real set is still described");
    assert_eq!(got.recovery_set_id, clean.recovery_set_id);
    assert_eq!(got.block_size, clean.block_size);
    assert_eq!(got.recovery_blocks_seen, clean.recovery_blocks_seen);
    let names = |s: &Par2Set| {
        s.files
            .iter()
            .map(|f| (f.name.clone(), f.length, f.blocks.len()))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        names(&got),
        names(&clean),
        "contamination cost the set files, lengths or block checksums"
    );
}

/// X5-15's CONTROL, and it must STAY green: the singular locator is
/// RIGHT to hand back both packets of a duplicated exponent, because the
/// repair side dedupes by exponent downstream. What was wrong is
/// COUNTING them as capacity - the count keyed its dedupe on the packet
/// MD5, and two slices at one exponent with different bytes are two MD5s
/// and one row of the coding matrix, so a volume holding 1 block of
/// repair power advertised 2 to the planner.
///
/// Asserted against the REAL fixture's set id and block size, so the
/// synthetic packets join the fixture's own set and the count is read off
/// `recovery_blocks_seen` - the field `get::settle` seeds `on_hand` from,
/// and the only one left since Y4b deleted `recovery_block_count`.
#[test]
fn duplicate_recovery_exponents_are_two_locators_and_one_block() {
    let real = parse_set();
    let set = real.recovery_set_id;
    let bs = real.block_size as usize;
    let slice = |exp: u32, fill: u8| {
        let mut b = exp.to_le_bytes().to_vec();
        b.extend_from_slice(&vec![fill; bs]);
        pkt(set, b"PAR 2.0\0RecvSlic", &b)
    };
    let mut vol = slice(0, 0x11);
    vol.extend_from_slice(&slice(0, 0x22));

    let locs = nzbkit::par2repair::recovery_slice_locators(&vol, &set);
    assert_eq!(locs.len(), 2, "both packets are located");
    let exps: std::collections::HashSet<u32> = locs.iter().map(|(e, _, _)| *e).collect();
    assert_eq!(exps.len(), 1, "they carry one distinct exponent");
    assert_eq!(
        Par2Set::parse(&[MAIN, &vol])
            .expect("the fixture's index plus these slices is one set")
            .recovery_blocks_seen,
        1,
        "the planner sizes its fetch on this number"
    );

    // And the real volume, whose four exponents are four genuine blocks,
    // is unchanged by the tighter key.
    assert_eq!(real.recovery_blocks_seen, 4);
}
