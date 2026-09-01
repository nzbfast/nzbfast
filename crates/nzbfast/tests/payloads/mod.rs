//! The ONE payload generator whose blocks do not repeat - for every
//! fixture whose verdict turns on where bytes came from.
//!
//! A sibling module the way `harness/mod.rs` and `scratch/mod.rs` are,
//! and for the reason those exist. Follow-up 13c.2 named FIVE private
//! copies of these fifteen lines; a census of the whole test tree on
//! 31 Aug 2026 found **eleven**, in eight suites across both the `e2e`
//! and `daemon` binaries, one of them a function-local `fn` inside a
//! single test. Every one was an independent rediscovery of one trap,
//! and two of them said so in their own doc comments without either
//! author knowing the other existed. That is the copy-paste-sibling
//! class this repo keeps writing gates about, and it had already gone
//! wrong in the usual way - see "the sixth copy did not have the
//! property it claimed" below.
//!
//! # The trap
//!
//! Both everyday fillers are ONE periodic sequence that a change of
//! seed merely SHIFTS, so blocks recur verbatim inside one file and
//! across two of its outputs:
//!
//! * `e2e.rs::payload(n, s)[i]` is `37i + s + (i >> 9)` mod 256. Since
//!   `37 * 512 == 0` mod 256, `payload(_, s + d)[i] == payload(_, s)[i
//!   + 512 * d]` for EVERY `i`, so the self-period is 131,072 bytes and
//!   two adjacent seeds share `len - 512` bytes verbatim.
//! * `daemon.rs::payload(n, s)[i]` is `29 * (i mod 256) + s` - no
//!   position term AT ALL, so the file is one 256-byte window written
//!   over and over and any two blocks a multiple of 256 apart are
//!   byte-identical. Measured over 400 kB at a 2,000-byte block: 184 of
//!   200 aligned blocks have an exact duplicate elsewhere in the SAME
//!   file, against 0 for this generator.
//!
//! PAR2 repair's extra-file adoption scan (`par2repair/adopt.rs`)
//! slides a rolling window over candidate files and takes any block
//! whose content it finds, and since follow-up 13a the last-resort
//! escalation reaches identified DAMAGED targets too. Over a payload
//! that repeats itself, a hole therefore heals with no parity at all -
//! so a fixture named for PAR2 repair greens whether or not its
//! recovery set was ever read.
//!
//! # What this one guarantees, measured
//!
//! splitmix64, eight bytes at a time. Over 400,000 bytes at both a
//! 2,000-byte and a 16,000-byte block: no aligned block equals another
//! at ANY offset in the same file, and no block of seed 5 occurs
//! anywhere in seed 6. So a hole here is a hole, and a block that gets
//! adopted was genuinely donated by another file.
//!
//! Use it for anything that damages a payload and then asserts a
//! rebuilt/adopted count, a decline, or which mechanism healed the job.
//! `payload` stays right for everything else and is deliberately
//! unchanged: 150-odd fixtures' PAR2 sets and MD5s are built on its
//! bytes.
//!
//! # The sixth copy did not have the property it claimed
//!
//! `e2e_norar::pins::unique_payload` was written on 30 Aug 2026 for
//! exactly this job - "NO self-similarity at PAR2-block distances...
//! Use it for anything that asserts WHERE bytes came from" - and was in
//! the class it was written to escape. It was `(i * 2654435761 + seed)
//! >> 24`, affine in `i`, so a seed change is a SHIFT just as
//! `payload`'s is: seed `s + 1` is seed `s` displaced by 61,495 bytes,
//! and 199 of 200 blocks of one are found somewhere in the other. Worse,
//! the multiplier is the golden ratio, so by the three-distance theorem
//! its near-period is a FIBONACCI number - `f(i) == f(i + 10946)` for
//! 99.51% of `i` over 200 kB, which at a 2,000-byte block left 53 of
//! 200 blocks with an exact duplicate elsewhere in the same file. Its
//! two rows assert exact adopted/rebuilt counts and passed anyway, on
//! the geometry they happened to use. Nobody had measured. That is the
//! argument for one copy rather than eleven: a private generator is
//! judged by its doc comment, and a doc comment is not a measurement.
//!
//! # What each copy had measured before it was folded in
//!
//! Kept because each is a real observation about a real fixture, and
//! deleting them to tidy the files they lived in would lose the only
//! record that this trap bites in practice:
//!
//! * `e2e_faults::unique_payload` - nine e2e fixtures reach the
//!   adoption scan at all, and FOUR were healing damage with ZERO
//!   blocks rebuilt from parity, because a block sits verbatim 131,072
//!   bytes further into the same file
//!   (`research/E2E-PARITY-BUDGET-CENSUS-2026-08-30.md`).
//! * `e2e_multiset::unshared_payload` - over three 400,000-byte tracks
//!   at `payload(_, i * 11)`, all 250 of track01's damaged 200-byte
//!   blocks appear verbatim inside track02 and vice versa; the repair
//!   read `0 block(s) rebuilt ... 250 block(s) adopted from
//!   track02.bin`, a correct adoption of genuinely matching bytes and a
//!   useless test of Reed-Solomon per set.
//! * `e2e_repair::aperiodic` - 24 Aug 2026, "54 block(s) adopted from
//!   r.part2.rar", repair complete, job exit 0, recovery set never
//!   consulted.
//! * `e2e_norar::pins::unique_payload` - its first cut reported 15
//!   blocks adopted and 1 rebuilt where the split geometry says 12 and
//!   4, and the row still passed.
//! * `daemon_donor::unrepeating` - three "leg A must fail" rows were
//!   failing because the repair was not allowed to look, not because
//!   the bytes were gone; when 13a let the shortfall reach the sliding
//!   scan, leg A repaired itself out of its own file and Completed,
//!   byte-exact.
//! * `e2e_lateset::lone_payload` - the X5-24 write-up's "wholly missing
//!   member rebuilt from its own 100% parity" was in fact
//!   `blocks_rebuilt = 0` with all 18 blocks ADOPTED out of its two
//!   siblings, which on `payload` are shifted copies of it. A probe
//!   whose member is reachable inside another member cannot say
//!   anything about a set that has no bytes of its own.
//! * `daemon_ladder::unique_payload`, `e2e_residual::disjoint_payload`,
//!   `e2e_norar::twin_adopt::noise`, `e2e_qprog::peer_payload` and the
//!   local `disjoint` inside
//!   `e2e.rs::par_only_post_reconstructs_two_files_from_one_set` - each
//!   written from the same reasoning, none with a fresh measurement.
//!
//! # What is deliberately NOT folded in here
//!
//! The ENTROPY family is a different subject and must stay separate:
//! `e2e.rs::half_entropy`, `e2e.rs::incompressible`,
//! `e2e_split::compressible` and the two inline half-entropy loops in
//! `e2e.rs` exist to control how COMPRESSIBLE a payload is, so that a
//! RAR or 7z writer really compresses rather than silently storing.
//! Their names state the property their fixtures depend on, and this
//! one cannot: `unique_payload` is incompressible and could stand in
//! for `incompressible` alone, which would move seventeen unpacking
//! fixtures' archives and MD5s for no measured defect. `leak_soak.rs`
//! carries its own copies of two of them and is a third binary that
//! does not include this module.

/// Bytes with no repeated PAR2 block, at any alignment, within one
/// output or across two seeds. See the module header for what that
/// buys and when a fixture needs it.
///
/// splitmix64 rather than an xorshift only because it was the majority
/// among the copies this replaced; any of them would do. Seeds do not
/// have to be far apart - the guarantee is on the sequence, not on the
/// spacing - so a converted fixture keeps whatever seeds it had.
pub fn unique_payload(n: usize, seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(n + 8);
    let mut x = seed;
    while out.len() < n {
        x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        out.extend_from_slice(&(z ^ (z >> 31)).to_le_bytes());
    }
    out.truncate(n);
    out
}
