//! The two RECOVERY-SLICE COUNTERS held to the one selection predicate,
//! and to each other.
//!
//! M4-56 (30 Aug 2026) found that a RecvSlic packet whose body carries
//! more than one `block_size` is a slice plus padding, not garbage, and
//! moved both places that SELECT slices for a repair onto
//! [`nzbkit::par2repair::slice_fits_block`] (`>= bs`, and a genuinely
//! SHORT packet refused out loud rather than zero-extended). It left the
//! two places that COUNT slices spelling `== bs`, and for a day the
//! halves disagreed:
//!
//! * `get::settle::usable_slices_of` feeds the fetch planner's `on_hand`,
//!   so a padded post refetched volumes already on disk and read every
//!   resumed one as partial;
//! * `recovery::CensusEntry::count` feeds the tail give-up, which read
//!   every volume in the job dir as holding zero parity of its set.
//!
//! Both drifted in the SAFE direction - they under-count, so the planner
//! over-fetches and the repair then succeeds off slices the census said
//! were not there - which is exactly why nothing ever reported it. A
//! silent, self-correcting disagreement is the shape that survives; the
//! post just pays for the volumes over the wire.
//!
//! A THIRD counter joined them on 31 Aug 2026 (Y4b) and it is the one
//! that drifted the UNSAFE way. `Par2Set::recovery_blocks_seen` is built
//! by the PARSE, had no length test at all, and is what `get::settle`
//! SEEDS `on_hand` with before `usable_slices_of` adds to it - so an
//! over-count and an accurate count were being added together, and
//! `needed = damage - on_hand` came out too small. Its own agreement
//! with the finders is pinned in nzbkit
//! (`par2repair::unit_tests::slice_len_tests`); what is pinned HERE is
//! the arithmetic that only this scope can see, that the seed and the
//! addend are the same currency.
//!
//! So the pin is an AGREEMENT pin and not two separate expectations: the
//! same buffer is put to both counters and to the predicate itself, and
//! all three must return the same verdict. Re-inlining `== bs` at either
//! site reddens it. A child of `workers` (see `par_race_tests`) because
//! `cached_recovery_blocks` is `pub(super)` there and `usable_slices_of`
//! is `pub(super)` in `get::settle` - this is the only scope that can
//! see both halves at once, which is the whole point of the row.

use super::recovery::{CensusCache, cached_recovery_blocks};
use crate::get::settle::usable_slices_of;
use md5::Digest as _;

const SET: [u8; 16] = [9u8; 16];
/// A block size that is a multiple of 4, as the spec requires, and
/// small enough that a padded volume is cheap to build.
const BS: usize = 1024;

/// One structurally valid PAR2 packet: header plus body, sealed with the
/// packet MD5 the scanner checks (MD5 of set id + type + body). A packet
/// that failed that seal would be dropped before either counter saw it,
/// which would make every assertion below pass for the wrong reason.
fn build_packet(set_id: &[u8; 16], ptype: &[u8; 16], body: &[u8]) -> Vec<u8> {
    assert!(
        body.len().is_multiple_of(4),
        "PAR2 packet bodies are 4-byte aligned"
    );
    let len = 64 + body.len();
    let mut p = Vec::with_capacity(len);
    p.extend_from_slice(b"PAR2\0PKT");
    p.extend_from_slice(&(len as u64).to_le_bytes());
    p.extend_from_slice(&[0u8; 16]); // md5, filled below
    p.extend_from_slice(set_id);
    p.extend_from_slice(ptype);
    p.extend_from_slice(body);
    let digest: [u8; 16] = md5::Md5::digest(&p[32..]).into();
    p[16..32].copy_from_slice(&digest);
    p
}

/// A recovery volume of `exps.len()` intact RecvSlic packets whose slice
/// payloads are `data_len` bytes each - the block size plus padding, the
/// block size exactly, or short of it. The seal is recomputed either
/// way, so the LENGTH is the only thing unusual about any packet here.
fn volume(set_id: &[u8; 16], exps: &[u32], data_len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for &e in exps {
        let mut body = e.to_le_bytes().to_vec();
        body.resize(4 + data_len, 0xab);
        out.extend(build_packet(set_id, b"PAR 2.0\0RecvSlic", &body));
    }
    out
}

fn set_of(id: [u8; 16], bs: usize) -> nzbkit::par2::Par2Set {
    nzbkit::par2::Par2Set {
        recovery_set_id: id,
        block_size: bs as u64,
        files: Vec::new(),
        nonrecovery: Vec::new(),
        recovery_blocks_seen: 0,
    }
}

/// The census counter, reached the way production reaches it: through a
/// file on disk. `cached_recovery_blocks` returns its scan whether or
/// not the file is quiet enough to memoize, so nothing here backdates
/// mtime - that gate is `par_race_tests`' subject, not this one's.
fn census_count(tag: &str, vol: &[u8], bs: usize) -> usize {
    let dir = std::env::temp_dir().join(format!("nzbfast-slicelen-{}-{tag}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let p = dir.join("set.vol0+4.par2");
    std::fs::write(&p, vol).unwrap();
    let mut cache = CensusCache::new();
    let n = cached_recovery_blocks(&p, &SET, bs, &mut cache);
    let _ = std::fs::remove_dir_all(&dir);
    n
}

/// Y4 (31 Aug 2026), the follow-up M4-56 owed. Four RecvSlic packets,
/// one set, one block size, put to every site that turns a slice length
/// into a number - and they must all say the same thing.
#[test]
fn both_slice_counters_agree_with_the_selection_predicate() {
    let exps = [0u32, 1, 2, 3];
    // (padding delta, how many of the four are usable). Over-long is
    // usable and cut to the block on load; short cannot be extended
    // without inventing bytes (M4-40) and is refused.
    let cases: [(isize, usize); 5] = [(0, 4), (4, 4), (64, 4), (-4, 0), (-(BS as isize), 0)];
    let mut reached = 0;
    for (delta, want) in cases {
        let data_len = (BS as isize + delta) as usize;
        let vol = volume(&SET, &exps, data_len);
        let set = set_of(SET, BS);

        let predicate = if nzbkit::par2repair::slice_fits_block(data_len, BS) {
            exps.len()
        } else {
            0
        };
        let settle = usable_slices_of(&vol, &set);
        let census = census_count(&format!("d{delta}"), &vol, BS);

        assert_eq!(
            predicate, want,
            "slice_fits_block moved: {data_len} bytes against a {BS}-byte block"
        );
        assert_eq!(
            settle, want,
            "the fetch planner counted {settle} of four {data_len}-byte slices, \
             wanted {want} - a re-inlined `== bs` in get::settle::usable_slices_of \
             makes a padded post refetch volumes it already holds"
        );
        assert_eq!(
            census, want,
            "the tail give-up's census counted {census} of four {data_len}-byte \
             slices, wanted {want} - a re-inlined `== bs` in CensusEntry::count \
             reads a padded job dir as holding no parity at all"
        );
        assert_eq!(
            settle, census,
            "the two counters disagree on the same buffer at {data_len} bytes; \
             this is the M4-56 drift itself and its direction is silent"
        );
        reached += 1;
    }
    assert_eq!(reached, 5, "the case table was not walked");
}

/// The counters must agree PER SET as well as per length: a volume
/// carrying a foreign set's slices is nobody else's parity, whatever it
/// is padded to. The census reaches this differently from the planner -
/// it groups by `(set id, length)` and the planner filters by set id
/// before it ever sees a length - so the two roads are only equivalent
/// if both apply both halves of the rule.
#[test]
fn a_padded_volume_of_another_set_is_counted_by_neither() {
    let foreign = [7u8; 16];
    let vol = volume(&foreign, &[0, 1, 2, 3], BS + 4);
    assert_eq!(usable_slices_of(&vol, &set_of(SET, BS)), 0);
    assert_eq!(census_count("foreign", &vol, BS), 0);
    // And the same bytes DO count for the set that owns them, so the
    // zero above is a set-id verdict and not an inert scanner.
    assert_eq!(usable_slices_of(&vol, &set_of(foreign, BS)), 4);
}

/// A minimal but STRUCTURALLY REAL index for `SET`: a Main packet
/// declaring the block size and one file id, plus the FileDesc that id
/// needs to resolve. Built rather than faked because the count under
/// test is produced by `Par2Set::parse`, and a set with no settled Main
/// has no block size to judge a slice against - `set_of` above cannot
/// stand in for it.
fn index(bs: usize) -> Vec<u8> {
    let fid = [0x41u8; 16];
    let mut main = (bs as u64).to_le_bytes().to_vec();
    main.extend_from_slice(&1u32.to_le_bytes());
    main.extend_from_slice(&fid);
    let mut out = build_packet(&SET, b"PAR 2.0\0Main\0\0\0\0", &main);
    // FileDesc: file id, whole-file MD5, first-16k MD5, length, name.
    let mut desc = fid.to_vec();
    desc.extend_from_slice(&[0xFFu8; 16]);
    desc.extend_from_slice(&[0xEEu8; 16]);
    desc.extend_from_slice(&(bs as u64).to_le_bytes());
    desc.extend_from_slice(b"x.bin\0\0\0");
    out.extend(build_packet(&SET, b"PAR 2.0\0FileDesc", &desc));
    out
}

/// Y4b (31 Aug 2026). The PARSE's own count against the fetch planner's,
/// on the same bytes - the two figures `get::settle` ADDS TOGETHER.
///
/// `on_hand` starts at each set's `recovery_blocks_seen` and every
/// prefetched or resumed volume adds `usable_slices_of` to it, so the two
/// have to be one currency or `needed = damage - on_hand` is arithmetic
/// over two different questions. Until this landed they were not: the
/// parse counted every exponent MENTIONED and the planner counted slices
/// that FIT, so a set whose bootstrap volume carried short slices seeded
/// `on_hand` with parity nothing could serve and the exact-fit fetch
/// bought too little.
///
/// This is the direction M4-56's own follow-up predicted and Y4 did not
/// reach. The job still repairs - `fetch_and_repair`'s last-resort
/// escalation buys every REMAINING volume and retries - so the cost is
/// the whole ladder where one rung would have done. What the escalation
/// cannot reach is a set whose only parity is the bootstrap already on
/// disk: `recovery_candidates` excludes what is already fetched, so there
/// is nothing left to buy and the verdict is a shortfall.
#[test]
fn the_parse_seed_and_the_planner_addend_are_the_same_currency() {
    let idx = index(BS);
    let exps = [0u32, 1, 2, 3];
    let cases: [(isize, usize); 5] = [(0, 4), (4, 4), (64, 4), (-4, 0), (-(BS as isize), 0)];
    let mut reached = 0;
    for (delta, want) in cases {
        let data_len = (BS as isize + delta) as usize;
        let vol = volume(&SET, &exps, data_len);
        let parsed = nzbkit::par2::Par2Set::parse(&[&idx, &vol]).expect("index plus volume");
        assert_eq!(
            parsed.block_size as usize, BS,
            "the index declares the grid"
        );
        let seed = parsed.recovery_blocks_seen;
        let addend = usable_slices_of(&vol, &parsed);
        assert_eq!(
            seed, want,
            "the parse seeded on_hand with {seed} of four {data_len}-byte \
             slices, wanted {want} - an over-count here makes `needed` too \
             SMALL and the exact-fit fetch buys too few volumes"
        );
        assert_eq!(
            seed, addend,
            "the seed and the addend disagree on the same buffer at {data_len} \
             bytes; get::settle adds these two together"
        );
        reached += 1;
    }
    assert_eq!(reached, 5, "the case table was not walked");
}

/// nzbkit's two finders report the length a packet ACTUALLY carries and
/// judge nothing - that is what lets one buffer answer several sets with
/// several block sizes off one read. Pinned here beside the consumers
/// because "fix the drift by filtering inside the finder" is the tempting
/// wrong move, and it would silently un-count a second set's slices.
#[test]
fn the_finders_still_report_raw_lengths() {
    let vol = volume(&SET, &[0, 1], BS + 4);
    let locs = nzbkit::par2repair::recovery_slice_locators(&vol, &SET);
    assert_eq!(locs.len(), 2, "both packets must reach the locator");
    for (_, _, len) in &locs {
        assert_eq!(*len, BS + 4, "the locator judged a length it should report");
    }
    let census = nzbkit::par2repair::recovery_slice_census(&vol);
    assert_eq!(
        census,
        vec![(SET, BS + 4, 2)],
        "the census judged a length it should group by"
    );
}
