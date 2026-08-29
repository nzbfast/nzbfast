//! M31 stage 1 mechanism tests: the placement gate, the content match,
//! the segment estimate, the block-level proof and the retry of a
//! rejected block against the next donor.

use super::*;
use crate::par2::{BlockCheck, Par2File, Par2Set};
use md5::{Digest, Md5};

fn check_of(bytes: &[u8], block_size: usize) -> BlockCheck {
    let mut padded = vec![0u8; block_size];
    padded[..bytes.len()].copy_from_slice(bytes);
    BlockCheck {
        md5: Md5::digest(&padded).into(),
        crc32: crc32fast::hash(&padded),
    }
}

/// A file of `length` pseudo-random bytes plus the PAR2 description a
/// set would carry for it.
fn synth_file(name: &str, length: usize, block_size: usize, seed: u64) -> (Vec<u8>, Par2File) {
    let mut data = Vec::with_capacity(length);
    let mut x = seed | 1;
    for _ in 0..length {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        data.push((x & 0xff) as u8);
    }
    let blocks = data
        .chunks(block_size)
        .map(|c| check_of(c, block_size))
        .collect();
    let head = &data[..data.len().min(16384)];
    (
        data.clone(),
        Par2File {
            file_id: [0u8; 16],
            name: name.to_string(),
            length: length as u64,
            md5: Md5::digest(&data).into(),
            md5_16k: Md5::digest(head).into(),
            blocks,
        },
    )
}

fn set_of(files: Vec<Par2File>, block_size: u64) -> Par2Set {
    Par2Set {
        recovery_set_id: [0u8; 16],
        block_size,
        files,
        recovery_blocks_seen: 0,
    }
}

// ---- holes_from_bad_blocks ----

#[test]
fn bad_blocks_become_byte_ranges_and_adjacent_ones_coalesce() {
    // 1000-byte file, 300-byte blocks: blocks 0..3, the last 100 long.
    let h = holes_from_bad_blocks(&[1, 2], 300, 1000);
    assert_eq!(h, vec![Span { off: 300, len: 600 }]);
}

#[test]
fn the_last_block_is_stated_at_its_real_length_not_the_block_size() {
    let h = holes_from_bad_blocks(&[3], 300, 1000);
    assert_eq!(h, vec![Span { off: 900, len: 100 }]);
}

#[test]
fn non_adjacent_bad_blocks_stay_separate_and_duplicates_collapse() {
    let h = holes_from_bad_blocks(&[3, 0, 0], 300, 1000);
    assert_eq!(
        h,
        vec![Span { off: 0, len: 300 }, Span { off: 900, len: 100 }]
    );
}

#[test]
fn a_bad_block_index_past_the_end_of_the_file_is_dropped() {
    assert!(holes_from_bad_blocks(&[99], 300, 1000).is_empty());
    assert!(holes_from_bad_blocks(&[0], 0, 1000).is_empty());
    assert!(holes_from_bad_blocks(&[0], 300, 0).is_empty());
}

// ---- match_by_content ----

#[test]
fn a_donor_file_with_the_same_bytes_matches_even_under_a_different_name() {
    let (_, tf) = synth_file("The.Show.S01E01.rar", 4096, 512, 7);
    let mut df = tf.clone();
    // The obfuscated repost's own name, and its own file id with it.
    df.name = "a3f19c2b8e.bin".to_string();
    df.file_id = [9u8; 16];
    let m = match_by_content(&set_of(vec![tf], 512), &set_of(vec![df], 512));
    assert_eq!(
        m,
        vec![FileMatch {
            target: 0,
            donor: 0,
            length: 4096
        }]
    );
}

#[test]
fn a_repack_with_the_same_name_and_length_but_different_bytes_matches_nothing() {
    let (_, tf) = synth_file("payload.r00", 4096, 512, 7);
    let (_, mut df) = synth_file("payload.r00", 4096, 512, 99);
    df.name = tf.name.clone();
    assert_eq!(df.length, tf.length);
    assert_ne!(df.md5, tf.md5);
    assert!(match_by_content(&set_of(vec![tf], 512), &set_of(vec![df], 512)).is_empty());
}

#[test]
fn a_differently_packed_posting_matches_nothing_at_all() {
    // The §282 case: another poster's upload of the same film. Different
    // volume sizes, different bytes, no digest in common.
    let (_, t0) = synth_file("a.r00", 4096, 512, 1);
    let (_, t1) = synth_file("a.r01", 4096, 512, 2);
    let (_, d0) = synth_file("b.part1.rar", 6144, 512, 3);
    let (_, d1) = synth_file("b.part2.rar", 2048, 512, 4);
    assert!(match_by_content(&set_of(vec![t0, t1], 512), &set_of(vec![d0, d1], 512)).is_empty());
}

#[test]
fn a_donor_file_is_claimed_at_most_once() {
    let (_, f) = synth_file("dup", 1024, 256, 5);
    let target = set_of(vec![f.clone(), f.clone()], 256);
    let donor = set_of(vec![f.clone()], 256);
    let m = match_by_content(&target, &donor);
    assert_eq!(m.len(), 1, "one donor file cannot serve two targets");
    assert_eq!(m[0].target, 0);
}

#[test]
fn a_zero_length_file_is_never_matched() {
    let mut f = synth_file("empty", 16, 8, 3).1;
    f.length = 0;
    let g = f.clone();
    assert!(match_by_content(&set_of(vec![f], 8), &set_of(vec![g], 8)).is_empty());
}

#[test]
fn a_matching_length_and_md5_with_a_disagreeing_head_hash_is_refused() {
    let (_, tf) = synth_file("x", 2048, 512, 11);
    let mut df = tf.clone();
    df.md5_16k = [0u8; 16];
    assert!(match_by_content(&set_of(vec![tf], 512), &set_of(vec![df], 512)).is_empty());
}

// ---- placement_ok ----

fn place(file_size: u64, off: u64, len: u64) -> Placement {
    Placement {
        file_size,
        off,
        len,
        declared_end: off + len,
    }
}

#[test]
fn a_donor_article_that_fits_the_file_passes_the_placement_gate() {
    assert!(placement_ok(&place(1000, 300, 300), 1000));
}

#[test]
fn a_donor_article_declaring_a_different_file_size_is_refused() {
    // The same segment index of a DIFFERENT encode: plausible id,
    // wrong file. This is the gate that catches it.
    assert!(!placement_ok(&place(999, 300, 300), 1000));
}

#[test]
fn a_truncated_donor_body_is_refused_by_its_own_declared_range() {
    let mut p = place(1000, 300, 300);
    p.len = 120; // 180 bytes short of what =ypart end= promised
    assert!(!placement_ok(&p, 1000));
}

#[test]
fn a_donor_article_running_off_the_end_of_the_file_is_refused() {
    assert!(!placement_ok(&place(1000, 900, 200), 1000));
    assert!(!placement_ok(&place(1000, 1000, 10), 1000));
}

#[test]
fn an_empty_body_is_refused() {
    assert!(!placement_ok(&place(1000, 0, 0), 1000));
}

#[test]
fn a_single_part_post_declaring_no_ypart_is_judged_on_its_span_alone() {
    let p = Placement {
        file_size: 400,
        off: 0,
        len: 400,
        declared_end: 0,
    };
    assert!(placement_ok(&p, 400));
    assert!(!placement_ok(&p, 401));
}

// ---- candidate_segments ----

#[test]
fn the_segment_estimate_picks_the_articles_over_the_hole() {
    // Ten equal segments over a 10,000-byte file: segment i covers
    // [1000i, 1000i+1000).
    let enc = vec![1024u64; 10];
    let want = [Span {
        off: 3200,
        len: 400,
    }];
    assert_eq!(candidate_segments(&enc, 10_000, &want, 0), vec![3]);
}

#[test]
fn a_hole_spanning_a_segment_boundary_asks_for_both() {
    let enc = vec![1024u64; 10];
    let want = [Span {
        off: 2900,
        len: 300,
    }];
    assert_eq!(candidate_segments(&enc, 10_000, &want, 0), vec![2, 3]);
}

#[test]
fn slack_widens_the_guess_to_the_neighbours() {
    let enc = vec![1024u64; 10];
    let want = [Span {
        off: 3200,
        len: 400,
    }];
    assert_eq!(candidate_segments(&enc, 10_000, &want, 1000), vec![2, 3, 4]);
}

#[test]
fn uneven_encoded_sizes_still_land_on_the_right_segment() {
    // A short last article, as every real file has.
    let enc = vec![1000, 1000, 1000, 200];
    let want = [Span { off: 3150, len: 10 }];
    // Total 3200 encoded over a 3200-byte file: segment 3 covers
    // [3000, 3200).
    assert_eq!(candidate_segments(&enc, 3200, &want, 0), vec![3]);
}

#[test]
fn the_estimate_does_not_overflow_on_a_large_file() {
    // 40 GB in 4 MB articles: `cum * length` is far past u64 if the
    // ratio is not taken in u128.
    let enc = vec![4_000_000u64; 10_000];
    let length = 40_000_000_000u64;
    let want = [Span {
        off: 39_999_000_000,
        len: 1000,
    }];
    let got = candidate_segments(&enc, length, &want, 0);
    assert_eq!(
        got,
        vec![9999],
        "the tail hole must map to the tail article"
    );
}

#[test]
fn nothing_wanted_or_nothing_declared_asks_for_nothing() {
    assert!(candidate_segments(&[1024], 1000, &[], 0).is_empty());
    assert!(candidate_segments(&[], 1000, &[Span { off: 0, len: 1 }], 0).is_empty());
    assert!(candidate_segments(&[0, 0], 1000, &[Span { off: 0, len: 1 }], 0).is_empty());
    assert!(candidate_segments(&[1024], 0, &[Span { off: 0, len: 1 }], 0).is_empty());
}

// ---- BlockHealer ----

#[test]
fn a_donor_article_covering_a_whole_bad_block_heals_it() {
    let (data, f) = synth_file("v.r00", 4096, 512, 21);
    let mut h = BlockHealer::new(&f.blocks, 512, f.length, &[3]);
    assert_eq!(
        h.wanted(),
        vec![Span {
            off: 1536,
            len: 512
        }]
    );
    // A 1024-byte donor article covering blocks 2 and 3.
    assert_eq!(
        h.offer(1024, &data[1024..2048]),
        512,
        "only block 3 wanted it"
    );
    let out = h.take_healed();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].block, 3);
    assert_eq!(out[0].off, 1536);
    assert_eq!(out[0].bytes, data[1536..2048].to_vec());
    assert_eq!(h.healed(), 1);
    assert_eq!(h.rejected(), 0);
    assert!(h.is_empty());
}

#[test]
fn a_donor_with_corrupt_bytes_is_rejected_and_nothing_is_handed_out() {
    let (data, f) = synth_file("v.r00", 4096, 512, 22);
    let mut h = BlockHealer::new(&f.blocks, 512, f.length, &[1]);
    let mut bad = data[512..1024].to_vec();
    bad[7] ^= 0x40; // one flipped bit
    h.offer(512, &bad);
    assert!(
        h.take_healed().is_empty(),
        "a failing block is never handed out"
    );
    assert_eq!(h.rejected(), 1);
    assert_eq!(h.healed(), 0);
    assert!(
        h.is_empty(),
        "it left the open set when it was judged - it comes back only          if a caller reopens it for the NEXT donor"
    );
}

#[test]
fn a_partly_covered_block_stays_wanted_until_the_rest_arrives() {
    let (data, f) = synth_file("v.r00", 4096, 512, 23);
    let mut h = BlockHealer::new(&f.blocks, 512, f.length, &[2]);
    h.offer(1024, &data[1024..1300]);
    assert!(h.take_healed().is_empty(), "half a block proves nothing");
    assert_eq!(
        h.wanted(),
        vec![Span {
            off: 1024,
            len: 512
        }]
    );
    // The remainder, read back off the disk copy - judged by the same
    // check as the borrowed half.
    h.offer(1300, &data[1300..1536]);
    let out = h.take_healed();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].bytes, data[1024..1536].to_vec());
}

#[test]
fn a_short_final_block_heals_at_its_real_length() {
    // 1100 bytes in 512-byte blocks: block 2 is 76 bytes long.
    let (data, f) = synth_file("tail.bin", 1100, 512, 24);
    assert_eq!(f.blocks.len(), 3);
    let mut h = BlockHealer::new(&f.blocks, 512, f.length, &[2]);
    assert_eq!(h.wanted(), vec![Span { off: 1024, len: 76 }]);
    h.offer(1024, &data[1024..1100]);
    let out = h.take_healed();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].bytes.len(), 76);
    assert_eq!(out[0].bytes, data[1024..1100].to_vec());
}

#[test]
fn several_bad_blocks_heal_independently_and_one_bad_donor_costs_only_its_own() {
    let (data, f) = synth_file("v.r00", 4096, 512, 25);
    let mut h = BlockHealer::new(&f.blocks, 512, f.length, &[1, 5, 6]);
    assert_eq!(
        h.wanted(),
        vec![
            Span { off: 512, len: 512 },
            Span {
                off: 2560,
                len: 1024
            }
        ],
        "adjacent wanted blocks coalesce into one fetch range"
    );
    h.offer(512, &data[512..1024]);
    let mut bad = data[2560..3072].to_vec();
    bad[0] ^= 1;
    h.offer(2560, &bad);
    h.offer(3072, &data[3072..3584]);
    let mut out = h.take_healed();
    out.sort_by_key(|x| x.block);
    assert_eq!(out.iter().map(|x| x.block).collect::<Vec<_>>(), vec![1, 6]);
    assert_eq!(h.rejected(), 1);
    assert!(h.is_empty());
}

#[test]
fn bytes_outside_every_wanted_block_are_ignored() {
    let (data, f) = synth_file("v.r00", 4096, 512, 26);
    let mut h = BlockHealer::new(&f.blocks, 512, f.length, &[7]);
    assert_eq!(h.offer(0, &data[0..512]), 0);
    assert_eq!(h.used(), 0);
    assert!(!h.is_empty());
}

#[test]
fn a_block_with_no_checksum_behind_it_is_never_opened() {
    // A set whose IFSC packet did not survive parsing states nothing
    // about block 9, so nothing may be accepted for it.
    let (_, f) = synth_file("v.r00", 4096, 512, 27);
    let h = BlockHealer::new(&f.blocks, 512, f.length, &[9]);
    assert!(h.is_empty());
    assert_eq!(BlockHealer::new(&[], 512, 4096, &[0]).wanted(), Vec::new());
}

#[test]
fn an_offer_landing_across_two_wanted_blocks_fills_both() {
    let (data, f) = synth_file("v.r00", 4096, 512, 28);
    let mut h = BlockHealer::new(&f.blocks, 512, f.length, &[2, 3]);
    assert_eq!(h.offer(1024, &data[1024..2048]), 1024);
    let out = h.take_healed();
    assert_eq!(out.len(), 2);
    assert_eq!(h.healed(), 2);
}

#[test]
fn an_offer_overlapping_a_block_only_partly_takes_only_the_overlap() {
    let (data, f) = synth_file("v.r00", 4096, 512, 29);
    let mut h = BlockHealer::new(&f.blocks, 512, f.length, &[1]);
    // A donor article running from mid-block-0 to mid-block-1.
    assert_eq!(h.offer(256, &data[256..768]), 256);
    assert!(h.take_healed().is_empty());
    assert_eq!(h.offer(768, &data[768..1024]), 256);
    assert_eq!(h.take_healed().len(), 1);
}

// ---- the whole mechanism, end to end on the arithmetic ----

#[test]
fn a_complementary_damaged_pair_completes_with_no_recovery_block_spent() {
    // The M31 gate, as arithmetic: one release, two postings of the SAME
    // bytes, each missing a disjoint set of blocks. Every hole in the
    // target is covered by the donor and every borrowed block proves
    // against the target's own set.
    let block = 512u64;
    let (data, tf) = synth_file("The.Release.part01.rar", 8192, 512, 31);
    // The donor's set: same bytes, obfuscated name, own file id.
    let mut df = tf.clone();
    df.name = "9f2c40aa11.dat".to_string();
    df.file_id = [7u8; 16];
    let m = match_by_content(&set_of(vec![tf.clone()], block), &set_of(vec![df], block));
    assert_eq!(m.len(), 1);

    // The target lost blocks 2, 3 and 11; the donor posting is missing
    // 0 and 1, which the target has.
    let bad = [2usize, 3, 11];
    let mut h = BlockHealer::new(&tf.blocks, block, tf.length, &bad);
    let want = h.wanted();
    assert_eq!(
        want,
        vec![
            Span {
                off: 1024,
                len: 1024
            },
            Span {
                off: 5632,
                len: 512
            }
        ]
    );

    // Which donor articles to ask for: sixteen 512-byte parts, so the
    // estimate is exact and asks for exactly the four that overlap.
    let enc = vec![700u64; 16];
    let segs = candidate_segments(&enc, tf.length, &want, 0);
    assert_eq!(segs, vec![2, 3, 11]);

    // Each arrives, self-describing. The placement gate passes, the
    // bytes go in.
    for s in segs {
        let off = s as u64 * block;
        let body = &data[off as usize..(off + block) as usize];
        let p = Placement {
            file_size: tf.length,
            off,
            len: body.len() as u64,
            declared_end: off + body.len() as u64,
        };
        assert!(placement_ok(&p, m[0].length));
        h.offer(p.off, body);
    }

    let mut out = h.take_healed();
    out.sort_by_key(|x| x.block);
    assert_eq!(
        out.iter().map(|x| x.block).collect::<Vec<_>>(),
        bad.to_vec()
    );
    assert_eq!(h.rejected(), 0);
    assert!(h.is_empty(), "no hole left for PAR2 repair to spend on");

    // And the rebuilt file verifies whole against the target's own set.
    let mut disk = data.clone();
    for hl in out {
        let at = hl.off as usize;
        disk[at..at + hl.bytes.len()].copy_from_slice(&hl.bytes);
    }
    assert_eq!(disk, data);
    assert!(crate::par2::verify_file(&tf, block, &disk).md5_ok);
}

#[test]
fn a_donor_serving_the_wrong_encode_heals_nothing_and_writes_nothing() {
    // Same length, different bytes - a repack. `match_by_content`
    // already refused it, but the healer is the second gate: even if a
    // caller ignored the first, no block is handed out.
    let block = 512u64;
    let (_, tf) = synth_file("real.r00", 4096, 512, 41);
    let (other, _) = synth_file("repack.r00", 4096, 512, 42);
    let mut h = BlockHealer::new(&tf.blocks, block, tf.length, &[0, 1]);
    h.offer(0, &other[0..1024]);
    assert!(h.take_healed().is_empty());
    assert_eq!(h.rejected(), 2);
    assert_eq!(h.healed(), 0);
}

// ---- first bytes win ----

#[test]
fn a_second_donor_cannot_overwrite_a_range_the_first_already_filled() {
    let (data, f) = synth_file("v.r00", 4096, 512, 51);
    let mut h = BlockHealer::new(&f.blocks, 512, f.length, &[0]);
    assert_eq!(h.offer(0, &data[0..512]), 512);
    // A second donor offering the same range, corrupt. It must land
    // nowhere: the block is already proved-able and its verdict must
    // not depend on who spoke last.
    let mut bad = data[0..512].to_vec();
    bad[3] ^= 0xff;
    assert_eq!(h.offer(0, &bad), 0, "an already-filled range takes nothing");
    let out = h.take_healed();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].bytes, data[0..512].to_vec());
    assert_eq!(h.rejected(), 0);
}

#[test]
fn a_later_offer_fills_only_the_gaps_around_what_is_already_there() {
    let (data, f) = synth_file("v.r00", 4096, 512, 52);
    let mut h = BlockHealer::new(&f.blocks, 512, f.length, &[0]);
    // A donor covering the middle third only.
    assert_eq!(h.offer(170, &data[170..340]), 170);
    assert!(h.take_healed().is_empty());
    // A whole-block offer now contributes only the two ends.
    assert_eq!(h.offer(0, &data[0..512]), 512 - 170);
    let out = h.take_healed();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].bytes, data[0..512].to_vec());
}

#[test]
fn three_disjoint_offers_in_any_order_rebuild_the_same_block() {
    let (data, f) = synth_file("v.r00", 4096, 512, 53);
    let order = [(340usize, 512usize), (0, 170), (170, 340)];
    let mut h = BlockHealer::new(&f.blocks, 512, f.length, &[0]);
    let mut wrote = 0;
    for (s, e) in order {
        wrote += h.offer(s as u64, &data[s..e]);
    }
    assert_eq!(wrote, 512);
    let out = h.take_healed();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].bytes, data[0..512].to_vec());
}

#[test]
fn an_offer_wholly_inside_an_already_filled_run_takes_nothing() {
    let (data, f) = synth_file("v.r00", 4096, 512, 54);
    let mut h = BlockHealer::new(&f.blocks, 512, f.length, &[0]);
    h.offer(0, &data[0..400]);
    assert_eq!(h.offer(100, &data[100..200]), 0);
    assert_eq!(h.offer(300, &data[300..512]), 112, "only the tail is new");
    assert_eq!(h.take_healed().len(), 1);
}

#[test]
fn a_healer_whose_blocks_are_all_covered_wants_nothing_more_before_it_is_judged() {
    let (data, f) = synth_file("v.r00", 4096, 512, 55);
    let mut h = BlockHealer::new(&f.blocks, 512, f.length, &[1, 2]);
    assert!(!h.is_satisfied(), "two open blocks, nothing in them");
    h.offer(512, &data[512..1024]);
    assert!(!h.is_satisfied(), "one block still bare");
    h.offer(1024, &data[1024..1536]);
    assert!(
        h.is_satisfied(),
        "every byte is in hand, so more donor bodies would be wasted"
    );
    assert!(!h.is_empty(), "and yet nothing has been PROVED yet");
    assert_eq!(h.take_healed().len(), 2);
    assert!(h.is_empty() && h.is_satisfied());
}

// ---- retrying a rejected block against another donor ----

#[test]
fn a_block_one_donor_got_wrong_heals_from_the_next_after_it_is_reopened() {
    let (data, f) = synth_file("v.r00", 4096, 512, 61);
    let mut h = BlockHealer::new(&f.blocks, 512, f.length, &[1]);
    // Donor A serves a corrupt copy of the whole block.
    let mut bad = data[512..1024].to_vec();
    bad[9] ^= 0x11;
    assert_eq!(h.offer(512, &bad), 512);
    assert!(
        h.take_healed().is_empty(),
        "a failing block is not handed out"
    );
    assert_eq!(h.rejected_blocks(), &[1], "and its identity is kept");
    assert!(h.is_empty(), "it left the open set when it was judged");
    // Re-opened for the next donor, EMPTY: nothing donor A wrote
    // survives, so first-bytes-win is untouched.
    assert_eq!(h.reopen_rejected(), 1);
    assert!(h.rejected_blocks().is_empty(), "the retry list is drained");
    assert_eq!(
        h.wanted(),
        vec![Span { off: 512, len: 512 }],
        "the block is wanted again, whole"
    );
    assert!(!h.is_satisfied(), "and the pass must keep asking for it");
    // Donor B serves the real bytes.
    assert_eq!(h.offer(512, &data[512..1024]), 512);
    let out = h.take_healed();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].block, 1);
    assert_eq!(out[0].bytes, data[512..1024].to_vec());
    assert_eq!(h.healed(), 1);
    assert_eq!(h.rejected(), 1, "the refused attempt is still counted");
}

#[test]
fn reopening_never_brings_back_a_block_that_was_already_proved() {
    let (data, f) = synth_file("v.r00", 4096, 512, 62);
    let mut h = BlockHealer::new(&f.blocks, 512, f.length, &[0, 1]);
    h.offer(0, &data[0..512]);
    let mut bad = data[512..1024].to_vec();
    bad[1] ^= 0x08;
    h.offer(512, &bad);
    assert_eq!(h.take_healed().len(), 1, "block 0 proved, block 1 refused");
    assert_eq!(h.rejected_blocks(), &[1]);
    assert_eq!(h.reopen_rejected(), 1);
    assert_eq!(
        h.wanted(),
        vec![Span { off: 512, len: 512 }],
        "only the refused one comes back - an accepted block is gone for good"
    );
}

#[test]
fn a_second_donor_that_is_wrong_too_leaves_the_block_for_repair() {
    let (data, f) = synth_file("v.r00", 4096, 512, 63);
    let mut h = BlockHealer::new(&f.blocks, 512, f.length, &[2]);
    for salt in [0x01u8, 0x02] {
        let mut bad = data[1024..1536].to_vec();
        bad[5] ^= salt;
        h.offer(1024, &bad);
        assert!(h.take_healed().is_empty());
        h.reopen_rejected();
    }
    assert_eq!(h.healed(), 0);
    assert_eq!(h.rejected(), 2, "two attempts refused, one block");
    assert!(!h.is_empty(), "still open, and nothing was ever handed out");
}

#[test]
fn reopening_with_nothing_rejected_is_a_no_op() {
    let (data, f) = synth_file("v.r00", 4096, 512, 64);
    let mut h = BlockHealer::new(&f.blocks, 512, f.length, &[0]);
    assert_eq!(h.reopen_rejected(), 0);
    h.offer(0, &data[0..512]);
    assert_eq!(h.take_healed().len(), 1);
    assert_eq!(h.reopen_rejected(), 0);
    assert!(h.is_empty() && h.is_satisfied());
}

#[test]
fn an_empty_healer_is_satisfied() {
    assert!(BlockHealer::new(&[], 512, 4096, &[]).is_satisfied());
}

// ---- the calibrated estimate ----

/// A sub-`slack` file: the blind guess covers all of it, so every
/// segment is a candidate however small the hole. That is the whole
/// defect, and one arrival is the whole fix.
#[test]
fn one_arrival_cuts_a_sub_slack_file_to_the_segment_that_really_covers_the_hole() {
    // 900,000 bytes in three articles of 300,000, each posted as
    // 312,000 encoded - a 4% yEnc inflation, which is ordinary.
    let enc = vec![312_000u64; 3];
    let want = [Span {
        off: 400_000,
        len: 65_536,
    }];
    // Blind, with the caller's own 1 MiB: the whole file, three bodies
    // for a 64 KiB hole one of them covers on its own.
    assert_eq!(
        candidate_segments(&enc, 900_000, &want, 1 << 20),
        vec![0, 1, 2],
        "the guess is wider than the file, so it asks for the file"
    );
    // Any one of the three, arriving and saying where it sat, is enough
    // to leave exactly the one that carries the hole.
    for (index, off) in [(0usize, 0u64), (1, 300_000), (2, 600_000)] {
        assert_eq!(
            candidate_segments_anchored(
                &enc,
                900_000,
                &want,
                1 << 20,
                Some(SegAnchor { index, off })
            ),
            vec![1],
            "anchored on segment {index}"
        );
    }
}

#[test]
fn an_anchor_the_stated_sizes_contradict_is_ignored_rather_than_believed() {
    let enc = vec![312_000u64; 3];
    let want = [Span {
        off: 400_000,
        len: 65_536,
    }];
    let blind = candidate_segments(&enc, 900_000, &want, 1 << 20);
    for bad in [
        // Past the end of the file.
        SegAnchor {
            index: 1,
            off: 900_001,
        },
        // More bytes before it than there are encoded bytes before it,
        // which yEnc cannot produce - it never shrinks a payload.
        SegAnchor {
            index: 1,
            off: 312_001,
        },
        // Leaves less room after it than the rest of the file needs.
        SegAnchor { index: 2, off: 100 },
        // Not a segment of this file at all.
        SegAnchor {
            index: 9,
            off: 300_000,
        },
    ] {
        assert_eq!(
            candidate_segments_anchored(&enc, 900_000, &want, 1 << 20, Some(bad)),
            blind,
            "{bad:?} should have fallen back to the blind estimate"
        );
    }
}

#[test]
fn a_file_whose_encoded_sizes_are_its_decoded_sizes_calibrates_to_an_exact_fit() {
    // `total == length` forces `decoded == encoded` segment by segment,
    // so the fit is exact and the slack it derives is zero.
    let enc = vec![1000u64; 10];
    let want = [Span {
        off: 3200,
        len: 400,
    }];
    assert_eq!(
        candidate_segments_anchored(
            &enc,
            10_000,
            &want,
            1000,
            Some(SegAnchor {
                index: 5,
                off: 5000
            })
        ),
        vec![3],
        "no slack is owed when nothing inflated"
    );
}

/// A file's real geometry: per-article decoded sizes, and the encoded
/// sizes an NZB would state for them, each article inflating by its own
/// amount between 1.5% and 4.5% plus a header - which is what makes the
/// blind estimate an estimate.
fn geom(n: usize, dec: u64, length: u64, seed: u64) -> (Vec<u64>, Vec<u64>) {
    let mut d = vec![dec; n];
    d[n - 1] = length - dec * (n as u64 - 1);
    let mut s = seed;
    let enc = d
        .iter()
        .map(|&x| {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let pct = 150 + (s >> 33) % 300;
            x + x * pct / 10_000 + 100
        })
        .collect();
    (d, enc)
}

/// File offsets of every segment boundary, `offs[n] == length`.
fn true_offs(d: &[u64]) -> Vec<u64> {
    let mut o = vec![0u64];
    for &x in d {
        o.push(o.last().unwrap() + x);
    }
    o
}

/// Every segment that GENUINELY overlaps one of `want`.
fn really_overlaps(d: &[u64], want: &[Span]) -> Vec<usize> {
    let offs = true_offs(d);
    (0..d.len())
        .filter(|&i| {
            let s = Span {
                off: offs[i],
                len: d[i],
            };
            want.iter().any(|w| s.intersect(w).is_some())
        })
        .collect()
}

/// The one thing calibration may never do. A wasted body costs a body;
/// a segment wrongly dropped costs a hole that PAR2 then has to repair
/// for no reason, and the module docs put correctness above completion.
#[test]
fn the_calibrated_estimate_never_drops_a_segment_that_really_overlaps() {
    let shapes: &[(usize, u64, u64)] = &[
        (3, 300_000, 900_000),
        (8, 8_192, 65_536),
        (20, 786_432, 15_728_640),
        (120, 768_590, 92_000_000),
    ];
    let mut checked = 0usize;
    for &(n, dec, length) in shapes {
        for seed in 0..8u64 {
            let (d, enc) = geom(n, dec, length, seed * 7919 + 1);
            let offs = true_offs(&d);
            for hole in 0..11u64 {
                // Holes at eleven positions across the file, each a
                // couple of PAR2 blocks wide.
                let off = length * hole / 11;
                let want = [Span {
                    off,
                    len: (length / 17).max(1).min(length - off),
                }];
                let truth = really_overlaps(&d, &want);
                assert!(!truth.is_empty());
                for k in 0..n {
                    let got = candidate_segments_anchored(
                        &enc,
                        length,
                        &want,
                        1 << 20,
                        Some(SegAnchor {
                            index: k,
                            off: offs[k],
                        }),
                    );
                    for t in &truth {
                        assert!(
                            got.contains(t),
                            "shape {n}x{dec} seed {seed} hole at {off} anchored on {k}: \
                             dropped segment {t}, which really covers the hole"
                        );
                    }
                    assert!(got.windows(2).all(|w| w[0] < w[1]), "ascending and unique");
                    checked += 1;
                }
            }
        }
    }
    assert!(checked > 4000, "the sweep really ran: {checked}");
}

/// The same band as [`geom`], drawn once per REGION rather than per
/// article. An i.i.d. per-article draw makes the cumulative drift a
/// random walk that stays far inside one article's slack, so the sweep
/// above can never exercise what a real file does: escape density that
/// differs by whole regions, whose drift is proportional to the region.
fn geom_regions(n: usize, dec: u64, length: u64, seed: u64) -> (Vec<u64>, Vec<u64>) {
    let mut d = vec![dec; n];
    d[n - 1] = length - dec * (n as u64 - 1);
    let mut s = seed;
    let mut rng = move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s >> 33
    };
    let regions = 2 + (rng() % 4) as usize;
    let mut pct = vec![0u64; n];
    let mut at = 0usize;
    for r in 0..regions {
        let end = if r == regions - 1 {
            n
        } else {
            (at + 1 + (rng() as usize % n.div_ceil(regions).max(1))).min(n)
        };
        let p = 150 + rng() % 300;
        pct[at..end].iter_mut().for_each(|x| *x = p);
        at = end;
        if at == n {
            break;
        }
    }
    let enc = d
        .iter()
        .zip(&pct)
        .map(|(&x, &p)| x + x * p / 10_000 + 100)
        .collect();
    (d, enc)
}

/// The no-drop property under region-correlated inflation, which is the
/// profile that broke the fitted-line-plus-average-drift cut this
/// module used to ship: with 3.4%/1.0%/4.7% regions the true span of a
/// mid-file segment fell outside the averaged bracket, the recut
/// `continue`d past the one article covering the hole, and repair spent
/// recovery blocks on bytes the donor held. The interval bounds hold
/// for every profile, so this sweep must stay at zero drops.
#[test]
fn the_calibrated_estimate_survives_region_correlated_inflation() {
    let shapes: &[(usize, u64, u64)] = &[
        (20, 786_432, 15_728_640),
        (120, 768_590, 92_000_000),
        (564, 700_000, 394_800_000),
    ];
    let mut checked = 0usize;
    for &(n, dec, length) in shapes {
        for seed in 0..6u64 {
            let (d, enc) = geom_regions(n, dec, length, seed * 6151 + 3);
            let offs = true_offs(&d);
            for hole in 0..7u64 {
                let off = length * hole / 7;
                let want = [Span {
                    off,
                    len: (length / 17).max(1).min(length - off),
                }];
                let truth = really_overlaps(&d, &want);
                assert!(!truth.is_empty());
                // Anchors sampled across the file rather than all `n`,
                // to keep the big shape's sweep under a second.
                for k in (0..n).step_by((n / 19).max(1)) {
                    let got = candidate_segments_anchored(
                        &enc,
                        length,
                        &want,
                        1 << 20,
                        Some(SegAnchor {
                            index: k,
                            off: offs[k],
                        }),
                    );
                    for t in &truth {
                        assert!(
                            got.contains(t),
                            "shape {n}x{dec} seed {seed} hole at {off} anchored on {k}: \
                             dropped segment {t}, which really covers the hole"
                        );
                    }
                    checked += 1;
                }
            }
        }
    }
    assert!(checked > 700, "the sweep really ran: {checked}");
}

#[test]
fn ask_order_puts_the_segment_over_the_hole_first_and_keeps_the_set() {
    let enc = vec![312_000u64; 3];
    let want = [Span {
        off: 400_000,
        len: 65_536,
    }];
    let segs = candidate_segments(&enc, 900_000, &want, 1 << 20);
    assert_eq!(segs, vec![0, 1, 2]);
    let ordered = ask_order(&enc, 900_000, &want, &segs);
    assert_eq!(ordered[0], 1, "the one the estimate puts over the hole");
    let mut back = ordered.clone();
    back.sort_unstable();
    assert_eq!(back, segs, "re-ordered, never re-judged");
    // Two holes: both the segments over them come before the rest.
    let two = [
        Span {
            off: 10_000,
            len: 1000,
        },
        Span {
            off: 700_000,
            len: 1000,
        },
    ];
    let ordered = ask_order(&enc, 900_000, &two, &[0, 1, 2]);
    assert_eq!(ordered[2], 1, "the segment over neither hole goes last");
}

// ---- what the pass costs on the wire ----

/// Model the caller: walk the plan, re-cutting it from the nearest
/// article that has come back, and stop when every wanted byte is in
/// hand (`BlockHealer::is_satisfied`). Returns (bodies asked for,
/// segments that really covered a hole and were never asked for).
fn simulate(
    enc: &[u64],
    d: &[u64],
    length: u64,
    want: &[Span],
    dead: &[usize],
    cal: bool,
    order: bool,
) -> (usize, usize) {
    let offs = true_offs(d);
    let slack = 1 << 20;
    let mut plan = candidate_segments(enc, length, want, slack);
    if order {
        plan = ask_order(enc, length, want, &plan);
    }
    let mut anchors: Vec<SegAnchor> = Vec::new();
    let mut asked: Vec<usize> = Vec::new();
    let mut have: Vec<usize> = Vec::new();
    for &i in &plan {
        let near = anchors.iter().min_by_key(|a| a.index.abs_diff(i)).copied();
        if near.is_some()
            && !candidate_segments_anchored(enc, length, want, slack, near).contains(&i)
        {
            continue;
        }
        asked.push(i);
        if dead.contains(&i) {
            continue;
        }
        have.push(i);
        if cal {
            anchors.push(SegAnchor {
                index: i,
                off: offs[i],
            });
        }
        let covered = |w: &Span| {
            let mut at = w.off;
            while let Some(&k) = have.iter().find(|&&j| offs[j] <= at && offs[j] + d[j] > at) {
                at = offs[k] + d[k];
                if at >= w.end() {
                    return true;
                }
            }
            false
        };
        if want.iter().all(covered) {
            break;
        }
    }
    let missed = really_overlaps(d, want)
        .into_iter()
        .filter(|t| !asked.contains(t) && !dead.contains(t))
        .count();
    (asked.len(), missed)
}

/// What the two changes are worth, pinned. Column three is what ships
/// today; column four is what ships now.
///
/// The attribution is the reason both landed rather than one. ORDERING
/// carries a healthy donor, because the healer stops the ask the moment
/// every wanted byte is in hand, so asking for the likely segment first
/// stops it a body or two sooner. CALIBRATION carries a donor that is
/// itself damaged, which is not exotic in a pass that exists for
/// damaged postings: there the short-circuit never fires, the whole
/// candidate list gets walked, and pruning it is the only saving there
/// is - 8 bodies to 4 on the last row, where ordering alone saves
/// nothing at all.
#[test]
fn the_donor_bodies_one_pass_asks_for_are_pinned() {
    // name, segments, decoded per article, length, holes, dead in donor,
    // (blind, calibrated+ordered)
    let cases: &[(&str, usize, u64, u64, &[(u64, u64)], &[usize], usize, usize)] = &[
        (
            "sub-1-MiB file, one small hole",
            3,
            300_000,
            900_000,
            &[(400_000, 65_536)],
            &[],
            2,
            1,
        ),
        (
            "64 KiB in 8 articles, one PAR2 block",
            8,
            8_192,
            65_536,
            &[(16_384, 4_096)],
            &[],
            3,
            1,
        ),
        (
            "64 KiB in 8 articles, three blocks in two holes",
            8,
            8_192,
            65_536,
            &[(8_192, 8_192), (36_864, 4_096)],
            &[],
            5,
            3,
        ),
        (
            "700 MB in 955 articles, one hole",
            955,
            768_590,
            734_003_200,
            &[(400_000_000, 393_216)],
            &[],
            2,
            1,
        ),
        (
            "700 MB, three holes far apart",
            955,
            768_590,
            734_003_200,
            &[
                (40_000_000, 393_216),
                (400_000_000, 393_216),
                (700_000_000, 393_216),
            ],
            &[],
            12,
            5,
        ),
        (
            "700 MB, one hole spanning five articles",
            955,
            768_590,
            734_003_200,
            &[(400_000_000, 4_000_000)],
            &[],
            7,
            6,
        ),
        (
            "15 MB in 20 articles, one hole",
            20,
            786_432,
            15_728_640,
            &[(7_000_000, 262_144)],
            &[],
            3,
            2,
        ),
        (
            "64 KiB, one block, and the donor is damaged over it too",
            8,
            8_192,
            65_536,
            &[(16_384, 4_096)],
            &[1, 2, 3],
            8,
            4,
        ),
    ];
    for (name, n, dec, length, holes, dead, want_old, want_new) in cases {
        let (d, enc) = geom(*n, *dec, *length, 99);
        let want: Vec<Span> = holes.iter().map(|&(off, len)| Span { off, len }).collect();
        let (old, m0) = simulate(&enc, &d, *length, &want, dead, false, false);
        let (new, m1) = simulate(&enc, &d, *length, &want, dead, true, true);
        assert_eq!((old, new), (*want_old, *want_new), "{name}");
        assert_eq!(m0, 0, "{name}: the blind plan missed one");
        assert_eq!(m1, 0, "{name}: the calibrated plan missed one");
        assert!(new <= old, "{name}: never more bodies than before");
    }
}

#[test]
fn part_filled_names_only_the_blocks_a_donor_half_served() {
    let (data, f) = synth_file("v.r01", 4096, 512, 77);
    // Blocks 1, 3 and 5 are bad. Block 1 gets its first half only,
    // block 3 gets the lot, block 5 gets nothing at all.
    let mut h = BlockHealer::new(&f.blocks, 512, f.length, &[1, 3, 5]);
    assert!(h.part_filled().is_empty(), "nothing offered yet");
    assert_eq!(h.offer(512, &data[512..768]), 256, "half of block 1");
    assert_eq!(h.offer(1536, &data[1536..2048]), 512, "all of block 3");
    assert_eq!(
        h.part_filled(),
        vec![1],
        "only the HALF-served block: 3 is complete and 5 is untouched"
    );
    // A complete block leaves `open` when it is judged, and an
    // untouched one stays exactly where it was.
    assert_eq!(h.take_healed().len(), 1, "block 3 proved");
    assert_eq!(h.part_filled(), vec![1], "judging 3 does not disturb 1");
    // Completing block 1 takes it off the list too - the predicate is
    // "some bytes in, not enough to judge" and nothing else.
    assert_eq!(h.offer(768, &data[768..1024]), 256, "block 1's other half");
    assert!(
        h.part_filled().is_empty(),
        "block 1 is complete now, and 5 was never part-served"
    );
    assert_eq!(h.take_healed().len(), 1, "block 1 proved");
    // ...and a REJECTED block that is re-opened comes back EMPTY, so it
    // is not part-served either until something offers into it again.
    let mut h = BlockHealer::new(&f.blocks, 512, f.length, &[2]);
    let mut wrong = data[1024..1536].to_vec();
    wrong[0] ^= 0xff;
    assert_eq!(h.offer(1024, &wrong), 512);
    assert!(h.take_healed().is_empty(), "refused");
    assert_eq!(h.reopen_rejected(), 1);
    assert!(
        h.part_filled().is_empty(),
        "a re-opened block is a fresh empty assembly, not a part-served one"
    );
}
