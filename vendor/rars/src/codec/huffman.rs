use std::cmp::Reverse;
#[cfg(test)]
use std::collections::BinaryHeap;

/// Like [`lengths_for_frequencies`], but guarantees the returned code lengths
/// form a *complete* canonical prefix code (Kraft equality) whenever at least
/// one symbol is used.
///
/// Strict RAR 5 decoders build their tables with 7-Zip's
/// `k_BuildMode_Full_or_Empty`, which rejects any under-full table (a table
/// whose codes leave part of the code space unassigned). A frequency table
/// with a single used symbol otherwise yields one length-1 code — Kraft sum
/// `0.5` — and such archives decode fine in unRAR but fail in 7-Zip / WinRAR
/// with a spurious "Data Error". Real Huffman codes for two or more symbols are
/// already complete, so this only adjusts the degenerate single-symbol case (and
/// the rare uniform-length fallback), padding with phantom codes that are never
/// emitted.
pub(crate) fn complete_lengths_for_frequencies(frequencies: &[usize], max_bits: u8) -> Vec<u8> {
    let mut lengths = lengths_for_frequencies(frequencies, max_bits);
    if !is_complete_code(&lengths) {
        assign_flat_complete_code(&mut lengths);
    }
    lengths
}

/// Returns true if the non-zero code lengths form a complete prefix code
/// (Kraft sum exactly 1), or if the table is empty (no used symbol).
fn is_complete_code(lengths: &[u8]) -> bool {
    // Kraft sum in units of 2^-max_len, accumulated as an integer to avoid
    // floating point. A complete code has sum == 2^max_len.
    let max_len = lengths.iter().copied().max().unwrap_or(0);
    if max_len == 0 {
        return true; // empty table
    }
    let mut sum: u64 = 0;
    for &len in lengths {
        if len != 0 {
            sum += 1u64 << (max_len - len);
        }
    }
    sum == (1u64 << max_len)
}

/// Overwrites `lengths` with a complete near-uniform canonical code over the
/// currently-used symbols (those with a non-zero length), preserving symbol
/// order. A single used symbol is padded with one phantom length-1 code so the
/// result satisfies Kraft equality; an empty table is left untouched. Callers
/// that need a guaranteed-complete code (e.g. tables a strict decoder builds
/// with `Full`/`Full_or_Empty`) can mark used symbols with any non-zero length
/// and call this to normalise them.
pub(crate) fn assign_flat_complete_code(lengths: &mut [u8]) {
    let used: Vec<usize> = lengths
        .iter()
        .enumerate()
        .filter(|(_, &len)| len != 0)
        .map(|(symbol, _)| symbol)
        .collect();
    let n = used.len();
    if n == 0 {
        return;
    }
    for len in lengths.iter_mut() {
        *len = 0;
    }
    if n == 1 {
        lengths[used[0]] = 1;
        // Pad with one phantom length-1 code so the two codes fill the space.
        let phantom = if used[0] == 0 { 1 } else { 0 };
        if phantom < lengths.len() {
            lengths[phantom] = 1;
        }
        return;
    }
    // Complete "flat" code: with k = ceil(log2 n), assign `2^k - n` symbols
    // length k-1 and the remaining `2n - 2^k` symbols length k. This satisfies
    // Kraft equality exactly.
    let k = (usize::BITS - (n - 1).leading_zeros()) as u8; // ceil(log2 n)
    let cap = 1usize << k;
    let short_count = cap - n; // symbols at length k-1
    for (i, &symbol) in used.iter().enumerate() {
        lengths[symbol] = if i < short_count { k - 1 } else { k };
    }
}

pub(crate) fn lengths_for_frequencies(frequencies: &[usize], max_bits: u8) -> Vec<u8> {
    let used_count = frequencies
        .iter()
        .filter(|&&frequency| frequency != 0)
        .count();
    if used_count <= 1 {
        return uniform_lengths_for_frequencies(frequencies);
    }

    if let Some(lengths) = unconstrained_lengths_for_frequencies(frequencies, used_count, max_bits)
    {
        return lengths;
    }
    // nzbfast-local change, 7 Sep 2026; see VENDORING.md. The unconstrained
    // tree is deeper than the table can express, so build the OPTIMAL code of
    // that depth rather than throwing the frequencies away. This used to return
    // `uniform_lengths_for_frequencies`, a FLAT code putting every used symbol
    // at 8-9 bits; on the 256 MiB mixed corpus it fired on about one RAR 5 main
    // table in ten (79 of ~770 at a 32 MiB dictionary, 131 at 128 KiB, which
    // was the writer's default when this was measured) and cost 0.2 to 0.5%
    // of the archive. The flat code is still the
    // answer when no code of `max_bits` bits exists at all, which is exactly
    // when the alphabet does not fit in `2^max_bits` codes.
    package_merge_lengths_for_frequencies(frequencies, used_count, max_bits)
        .unwrap_or_else(|| uniform_lengths_for_frequencies(frequencies))
}

/// The plain (unconstrained) Huffman code for `frequencies`, or `None` when
/// some symbol needs more than `max_bits` bits. `used_count` is the number of
/// non-zero frequencies and is at least two.
fn unconstrained_lengths_for_frequencies(
    frequencies: &[usize],
    used_count: usize,
    max_bits: u8,
) -> Option<Vec<u8>> {
    let mut lengths = vec![0u8; frequencies.len()];
    // nzbfast-local change, 5 Sep 2026 - flat Huffman parent links; see VENDORING.md.
    // Node indexes are the original creation-order tie breaker. Each merge
    // records two parent links instead of visiting and joining symbol vectors.
    let mut parents = vec![0usize; 2 * used_count - 1];
    let mut nodes = Vec::with_capacity(used_count);
    let mut order = 0usize;
    for &frequency in frequencies {
        if frequency != 0 {
            nodes.push(Reverse((frequency, order)));
            order += 1;
        }
    }
    // Two queues instead of a binary heap (van Leeuwen). Once the leaves are
    // sorted, the merged sums come out non-decreasing on their own, so the
    // next-smallest node is always at the head of one of the two queues and
    // no sift is needed. The heap this replaced re-sifted ~400 symbols on
    // every table of every block; measured 3.2% off whole-archive creation on
    // a mixed 4 GiB corpus, and 10.0% on repetitive text (which rebuilds
    // tables far more often per byte) against a 0.93% A/A noise floor.
    //
    // Tie-breaking must match the heap exactly or the emitted code lengths
    // move. Both queues hold `(frequency, order)` and are compared as whole
    // tuples, and a leaf's `order` is always below a merged node's, so a
    // frequency tie still resolves to the leaf, as popping the heap did.
    nodes.sort_unstable_by_key(|node| node.0);
    let mut merged = Vec::<(usize, usize)>::with_capacity(used_count - 1);
    let mut leaf_head = 0usize;
    let mut merged_head = 0usize;
    let take = |leaf_head: &mut usize, merged_head: &mut usize, merged: &[(usize, usize)]| {
        let leaf_wins = *leaf_head < nodes.len()
            && (*merged_head == merged.len() || nodes[*leaf_head].0 <= merged[*merged_head]);
        if leaf_wins {
            let node = nodes[*leaf_head].0;
            *leaf_head += 1;
            node
        } else {
            let node = merged[*merged_head];
            *merged_head += 1;
            node
        }
    };
    while nodes.len() - leaf_head + merged.len() - merged_head > 1 {
        let (left_frequency, left) = take(&mut leaf_head, &mut merged_head, &merged);
        let (right_frequency, right) = take(&mut leaf_head, &mut merged_head, &merged);
        parents[left] = order;
        parents[right] = order;
        merged.push((left_frequency.saturating_add(right_frequency), order));
        order += 1;
    }
    debug_assert_eq!(order, parents.len());
    // Parents always have larger indexes than their children. Walking back
    // from the root converts links to depths in the same storage: a child's
    // parent has already been converted. The root's initialized zero is its depth.
    for node in (0..parents.len() - 1).rev() {
        let depth = parents[parents[node]] + 1;
        if depth > usize::from(max_bits) {
            return None;
        }
        parents[node] = depth;
    }
    let mut leaf = 0;
    for (symbol, &frequency) in frequencies.iter().enumerate() {
        if frequency != 0 {
            lengths[symbol] = parents[leaf] as u8;
            leaf += 1;
        }
    }
    Some(lengths)
}

/// nzbfast-local change, 7 Sep 2026; see VENDORING.md.
///
/// The optimal prefix code for `frequencies` in which no symbol exceeds
/// `max_bits` bits, by Larmore and Hirschberg's package-merge run as the coin
/// collector: `max_bits` lists of coins, list `l` holding one coin of value
/// `frequency` per used symbol plus the packages of the list below it, of which
/// the cheapest `2 * used_count - 2` are bought. A symbol's code length is the
/// number of lists whose bought prefix reached its coin.
///
/// Returns `None` when no such code exists, which is exactly
/// `used_count > 2^max_bits`. Otherwise the result is COMPLETE (Kraft sum
/// exactly one, since `2 * used_count - 2` coins are bought), never deeper than
/// `max_bits`, and of minimum total cost - so never worse than the flat code it
/// replaces, which is itself one of the codes package-merge minimises over.
///
/// Costs `used_count * max_bits` merge steps: at most 306 x 15 for a RAR 5 main
/// table, against tokenizing the 256 KiB block the table describes.
fn package_merge_lengths_for_frequencies(
    frequencies: &[usize],
    used_count: usize,
    max_bits: u8,
) -> Option<Vec<u8>> {
    let levels = usize::from(max_bits);
    if levels == 0 {
        return None;
    }
    // `1 << levels` is the number of codes a `levels`-deep table holds. A wider
    // shift than the word cannot be reached: the caller only lands here when
    // the unconstrained tree was deeper than `max_bits`, and no Huffman tree is
    // deeper than `used_count - 1`.
    if levels < usize::BITS as usize && used_count > (1usize << levels) {
        return None;
    }

    // Used symbols by ascending frequency, ties by symbol index, so the merge
    // below is deterministic and the code lengths come out non-increasing in
    // frequency. Weights are u128 because a package sums many frequencies and
    // the input is only bounded by `usize::MAX` per symbol.
    let mut symbols: Vec<(u128, usize)> = frequencies
        .iter()
        .enumerate()
        .filter(|(_, &frequency)| frequency != 0)
        .map(|(symbol, &frequency)| (frequency as u128, symbol))
        .collect();
    symbols.sort_unstable();
    let leaf_weights: Vec<u128> = symbols.iter().map(|&(weight, _)| weight).collect();

    // `bought[i]` records, for the list at depth `levels - i`, whether each coin
    // is a leaf (true) or a package of two coins from the list below (false).
    // The deepest list holds the leaf coins alone.
    let mut bought: Vec<Vec<bool>> = Vec::with_capacity(levels);
    bought.push(vec![true; used_count]);
    let mut below = leaf_weights.clone();
    let mut merged = Vec::new();
    for _ in 1..levels {
        let package_count = below.len() / 2;
        merged.clear();
        merged.reserve(used_count + package_count);
        let mut flags = Vec::with_capacity(used_count + package_count);
        let mut leaf = 0usize;
        let mut package = 0usize;
        while leaf < used_count || package < package_count {
            let package_weight = if package < package_count {
                Some(below[2 * package] + below[2 * package + 1])
            } else {
                None
            };
            let take_leaf = match package_weight {
                Some(weight) => leaf < used_count && leaf_weights[leaf] <= weight,
                None => true,
            };
            if take_leaf {
                merged.push(leaf_weights[leaf]);
                flags.push(true);
                leaf += 1;
            } else {
                merged.push(package_weight.expect("a package remains to buy"));
                flags.push(false);
                package += 1;
            }
        }
        std::mem::swap(&mut below, &mut merged);
        bought.push(flags);
    }

    // Buy the cheapest `2 * used_count - 2` coins of the shallowest list, then
    // walk down: the packages among a list's bought prefix are that list's
    // first packages, so they buy exactly twice as many coins one level deeper.
    let mut lengths = vec![0u8; frequencies.len()];
    let mut to_buy = 2 * used_count - 2;
    for flags in bought.iter().rev() {
        let here = to_buy.min(flags.len());
        let leaves = flags.iter().take(here).filter(|&&is_leaf| is_leaf).count();
        for &(_, symbol) in symbols.iter().take(leaves) {
            lengths[symbol] += 1;
        }
        to_buy = 2 * (here - leaves);
    }
    debug_assert!(lengths
        .iter()
        .zip(frequencies)
        .all(|(&length, &frequency)| (frequency == 0) == (length == 0)));
    debug_assert!(lengths.iter().all(|&length| length <= max_bits));
    Some(lengths)
}

pub(crate) fn lengths_for_frequency_array<const N: usize>(
    frequencies: &[usize; N],
    max_bits: u8,
) -> [u8; N] {
    let mut lengths = [0u8; N];
    lengths.copy_from_slice(&lengths_for_frequencies(frequencies, max_bits));
    lengths
}

pub(crate) fn uniform_lengths_for_frequencies(frequencies: &[usize]) -> Vec<u8> {
    let used_count = frequencies
        .iter()
        .filter(|&&frequency| frequency != 0)
        .count();
    let uniform_length = bits_for_symbol_count(used_count);
    frequencies
        .iter()
        .map(|&frequency| if frequency == 0 { 0 } else { uniform_length })
        .collect()
}

pub(crate) fn bits_for_symbol_count(count: usize) -> u8 {
    match count {
        0 | 1 => 1,
        _ => usize::BITS as u8 - (count - 1).leading_zeros() as u8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_assign_flat_complete_code(lengths: &mut [u8]) {
        let used: Vec<usize> = lengths
            .iter()
            .enumerate()
            .filter(|(_, &len)| len != 0)
            .map(|(symbol, _)| symbol)
            .collect();
        let n = used.len();
        if n == 0 {
            return;
        }
        for len in lengths.iter_mut() {
            *len = 0;
        }
        if n == 1 {
            lengths[used[0]] = 1;
            // Pad with one phantom length-1 code so the two codes fill the space.
            let phantom = if used[0] == 0 { 1 } else { 0 };
            if phantom < lengths.len() {
                lengths[phantom] = 1;
            }
            return;
        }
        // Complete "flat" code: with k = ceil(log2 n), assign `2^k - n` symbols
        // length k-1 and the remaining `2n - 2^k` symbols length k. This satisfies
        // Kraft equality exactly.
        let k = (usize::BITS - (n - 1).leading_zeros()) as u8; // ceil(log2 n)
        let cap = 1usize << k;
        let short_count = cap - n; // symbols at length k-1
        for (i, &symbol) in used.iter().enumerate() {
            lengths[symbol] = if i < short_count { k - 1 } else { k };
        }
    }

    /// The two-queue builder must agree with the heap it replaced on EVERY
    /// input, not just on distinct frequencies: the emitted code lengths are
    /// part of the archive, so a tie broken the other way changes bytes.
    /// Case class 0 forces heavy ties (frequencies 0..6), class 1 forces
    /// `saturating_add` to actually saturate (frequencies near `usize::MAX`),
    /// and the rest are ordinary spreads.
    #[test]
    fn the_two_queue_builder_matches_the_heap_on_ties_and_saturated_sums() {
        let mut seed = 971u64;
        for case in 0..512 {
            let frequencies: Vec<_> = (0..(2 + case % 305))
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    match case % 4 {
                        0 => (seed % 7) as usize,
                        1 => usize::MAX - (seed % 32) as usize,
                        _ => (seed % 100_000) as usize,
                    }
                })
                .collect();
            let used = frequencies.iter().filter(|&&n| n != 0).count();
            if used < 2 {
                continue;
            }
            for max_bits in [8, 15, 32] {
                assert_eq!(
                    unconstrained_lengths_for_frequencies(&frequencies, used, max_bits),
                    reference_lengths_for_frequencies(&frequencies, max_bits),
                    "case {case} at max_bits {max_bits}"
                );
            }
        }
    }

    /// The symbol-vector Huffman reference the flat parent-link builder replaced,
    /// answering `None` where the tree is deeper than `max_bits` - the case the
    /// length limiter now takes over.
    fn reference_lengths_for_frequencies(frequencies: &[usize], max_bits: u8) -> Option<Vec<u8>> {
        let used_count = frequencies
            .iter()
            .filter(|&&frequency| frequency != 0)
            .count();
        if used_count <= 1 {
            return Some(uniform_lengths_for_frequencies(frequencies));
        }

        let mut lengths = vec![0u8; frequencies.len()];
        let mut heap = BinaryHeap::new();
        let mut order = 0usize;
        for (symbol, &frequency) in frequencies.iter().enumerate() {
            if frequency == 0 {
                continue;
            }
            heap.push(Reverse((frequency, order, vec![symbol])));
            order += 1;
        }

        while heap.len() > 1 {
            let Reverse((left_frequency, _, mut left_symbols)) =
                heap.pop().expect("frequency heap has a left node");
            let Reverse((right_frequency, _, mut right_symbols)) =
                heap.pop().expect("frequency heap has a right node");
            for &symbol in left_symbols.iter().chain(right_symbols.iter()) {
                lengths[symbol] += 1;
            }
            left_symbols.append(&mut right_symbols);
            heap.push(Reverse((
                left_frequency.saturating_add(right_frequency),
                order,
                left_symbols,
            )));
            order += 1;
        }

        if lengths.iter().any(|&length| length > max_bits) {
            None
        } else {
            Some(lengths)
        }
    }

    fn total_cost(frequencies: &[usize], lengths: &[u8]) -> u128 {
        frequencies
            .iter()
            .zip(lengths)
            .map(|(&frequency, &length)| frequency as u128 * u128::from(length))
            .sum()
    }

    /// The cost of the cheapest complete prefix code over the used symbols with
    /// no length above `max_bits`, by enumerating every length assignment. The
    /// oracle for the limiter, usable only on small alphabets.
    fn brute_force_optimal_cost(frequencies: &[usize], max_bits: u8) -> Option<u128> {
        let used: Vec<usize> = frequencies
            .iter()
            .enumerate()
            .filter(|(_, &frequency)| frequency != 0)
            .map(|(symbol, _)| symbol)
            .collect();
        if used.is_empty() || max_bits == 0 || max_bits >= 32 {
            return None;
        }
        let mut assignment = vec![1u8; used.len()];
        let mut best: Option<u128> = None;
        loop {
            let kraft: u64 = assignment
                .iter()
                .map(|&length| 1u64 << (max_bits - length))
                .sum();
            if kraft == 1u64 << max_bits {
                let cost: u128 = used
                    .iter()
                    .zip(&assignment)
                    .map(|(&symbol, &length)| frequencies[symbol] as u128 * u128::from(length))
                    .sum();
                best = Some(best.map_or(cost, |current: u128| current.min(cost)));
            }
            let mut digit = 0usize;
            loop {
                if digit == assignment.len() {
                    return best;
                }
                if assignment[digit] < max_bits {
                    assignment[digit] += 1;
                    break;
                }
                assignment[digit] = 1;
                digit += 1;
            }
        }
    }

    #[test]
    fn parent_index_huffman_tree_matches_symbol_vector_reference() {
        let mut seed = 0x213d_96abu32;
        for size in [0, 1, 2, 3, 4, 16, 20, 44, 64, 80, 256, 306, 512, 1024] {
            let mut cases = vec![vec![0; size], vec![1; size], vec![usize::MAX; size]];
            cases.push((0..size).map(|i| i + 1).collect());
            cases.push((0..size).map(|i| size - i).collect());
            cases.push((0..size).map(|i| usize::MAX - (i % 3)).collect());
            let mut a = 1usize;
            let mut b = 1usize;
            cases.push(
                (0..size)
                    .map(|_| {
                        let frequency = a;
                        (a, b) = (b, a.saturating_add(b));
                        frequency
                    })
                    .collect(),
            );
            if size != 0 {
                for symbol in [0, size - 1] {
                    let mut singleton = vec![0; size];
                    singleton[symbol] = 17;
                    cases.push(singleton);
                }
            }
            for _ in 0..8 {
                cases.push(
                    (0..size)
                        .map(|_| {
                            seed ^= seed << 13;
                            seed ^= seed >> 17;
                            seed ^= seed << 5;
                            (seed % 13) as usize
                        })
                        .collect(),
                );
            }
            for frequencies in cases {
                let used_count = frequencies
                    .iter()
                    .filter(|&&frequency| frequency != 0)
                    .count();
                for max_bits in [0, 1, 7, 15, 255] {
                    let reference = reference_lengths_for_frequencies(&frequencies, max_bits);
                    let actual = lengths_for_frequencies(&frequencies, max_bits);
                    if used_count > 1 {
                        assert_eq!(
                            unconstrained_lengths_for_frequencies(
                                &frequencies,
                                used_count,
                                max_bits
                            ),
                            reference
                        );
                    }
                    match &reference {
                        Some(expected) => assert_eq!(&actual, expected),
                        None => {
                            // The unconstrained tree was too deep, so the length
                            // limiter answered. Its code is complete, inside the
                            // cap and never dearer than the flat code it replaced
                            // - unless no code of that depth exists at all, when
                            // the flat code is still the answer.
                            let flat = uniform_lengths_for_frequencies(&frequencies);
                            if actual != flat {
                                assert!(actual.iter().all(|&length| length <= max_bits));
                                if max_bits <= 32 {
                                    assert!(kraft_sum_is_one(&actual));
                                }
                            }
                            assert!(
                                total_cost(&frequencies, &actual)
                                    <= total_cost(&frequencies, &flat)
                            );
                        }
                    }
                    if max_bits == 255 {
                        // The raw builder supports deeper trees than the
                        // 64-bit Kraft validator used by complete codes.
                        continue;
                    }
                    let mut complete = actual;
                    if !is_complete_code(&complete) {
                        reference_assign_flat_complete_code(&mut complete);
                    }
                    assert_eq!(
                        complete_lengths_for_frequencies(&frequencies, max_bits),
                        complete
                    );
                }
            }
        }
    }

    #[test]
    fn length_limited_codes_are_optimal_against_brute_force() {
        // Small alphabets, every complete code under the cap enumerated. Both
        // paths must be cost-optimal: the plain Huffman tree where it fits, the
        // package-merge limiter where it does not.
        let mut seed = 0x9e37_79b9u32;
        let mut limited = 0usize;
        for used_count in 2..=6usize {
            for max_bits in 2..=5u8 {
                if used_count > 1usize << max_bits {
                    continue;
                }
                let mut cases: Vec<Vec<usize>> = Vec::new();
                // Frequencies that force a chain-shaped tree, so the cap bites.
                let mut a = 1usize;
                let mut b = 1usize;
                cases.push(
                    (0..used_count)
                        .map(|_| {
                            let frequency = a;
                            (a, b) = (b, a + b);
                            frequency
                        })
                        .collect(),
                );
                cases.push((0..used_count).map(|i| 1usize << (2 * i)).collect());
                for _ in 0..160 {
                    cases.push(
                        (0..used_count)
                            .map(|_| {
                                seed ^= seed << 13;
                                seed ^= seed >> 17;
                                seed ^= seed << 5;
                                1 + (seed % 4096) as usize
                            })
                            .collect(),
                    );
                }
                for frequencies in cases {
                    if unconstrained_lengths_for_frequencies(&frequencies, used_count, max_bits)
                        .is_none()
                    {
                        limited += 1;
                    }
                    let lengths = lengths_for_frequencies(&frequencies, max_bits);
                    assert!(
                        lengths
                            .iter()
                            .all(|&length| (1..=max_bits).contains(&length)),
                        "{frequencies:?} at {max_bits} bits gave {lengths:?}"
                    );
                    assert!(kraft_sum_is_one(&lengths));
                    let optimal = brute_force_optimal_cost(&frequencies, max_bits)
                        .expect("a complete code exists inside the cap");
                    assert_eq!(
                        total_cost(&frequencies, &lengths),
                        optimal,
                        "{frequencies:?} at {max_bits} bits gave {lengths:?}"
                    );
                }
            }
        }
        assert!(
            limited > 0,
            "the cap never bit, so the limiter was never measured"
        );
    }

    #[test]
    fn adversarial_frequencies_stay_complete_inside_fifteen_bits() {
        // Fibonacci-like frequencies are the shape that overflows the 15-bit
        // RAR 5 cap: each new symbol hangs one level deeper than the last.
        for symbol_count in [40usize, 64, 128, 256, 306, 512] {
            let mut a = 1usize;
            let mut b = 1usize;
            let frequencies: Vec<usize> = (0..symbol_count)
                .map(|_| {
                    let frequency = a;
                    (a, b) = (b, a.saturating_add(b));
                    frequency
                })
                .collect();
            assert!(
                unconstrained_lengths_for_frequencies(&frequencies, symbol_count, 15).is_none(),
                "{symbol_count} Fibonacci frequencies should overflow 15 bits"
            );
            let lengths = lengths_for_frequencies(&frequencies, 15);
            assert!(lengths.iter().all(|&length| (1..=15).contains(&length)));
            assert!(
                kraft_sum_is_one(&lengths),
                "{symbol_count} symbols must yield a complete code"
            );
            // The flat code this replaced is one of the codes package-merge
            // minimises over, so the limiter can never be dearer than it.
            let flat = uniform_lengths_for_frequencies(&frequencies);
            assert!(total_cost(&frequencies, &lengths) < total_cost(&frequencies, &flat));
        }
    }

    #[test]
    fn a_deep_tailed_main_table_beats_the_flat_code() {
        // The RAR 5 main table's shape when the fallback fired: 306 symbols, a
        // few dominant ones and a long rare tail.
        let mut frequencies = vec![0usize; 306];
        for (symbol, frequency) in frequencies.iter_mut().enumerate().take(276) {
            *frequency = match symbol {
                0..=3 => 1 << 20,
                4..=15 => 1 << 14,
                _ => 1 + symbol % 3,
            };
        }
        assert!(unconstrained_lengths_for_frequencies(&frequencies, 276, 15).is_none());
        let lengths = lengths_for_frequencies(&frequencies, 15);
        let flat = uniform_lengths_for_frequencies(&frequencies);
        assert!(kraft_sum_is_one(&lengths));
        assert!(lengths.iter().all(|&length| length <= 15));
        assert!(
            total_cost(&frequencies, &lengths) < total_cost(&frequencies, &flat) / 2,
            "the flat code costs {} bits, the limited one {}",
            total_cost(&frequencies, &flat),
            total_cost(&frequencies, &lengths)
        );
    }

    #[test]
    fn an_alphabet_too_wide_for_the_cap_still_falls_back_to_flat() {
        // No prefix code of 3 bits covers 306 symbols, so there is nothing for
        // the limiter to return and the flat code remains the answer.
        let frequencies: Vec<usize> = (1..=306).collect();
        assert_eq!(
            lengths_for_frequencies(&frequencies, 3),
            uniform_lengths_for_frequencies(&frequencies)
        );
    }

    #[test]
    fn weighted_lengths_favour_common_symbols() {
        let frequencies = [1, 1, 16, 1];
        let lengths = lengths_for_frequencies(&frequencies, 15);

        assert!(lengths[2] < lengths[0]);
        assert!(lengths.iter().all(|&length| length <= 15));
    }

    #[test]
    fn excessive_lengths_fall_back_to_uniform_lengths() {
        let frequencies = (1..=1024).collect::<Vec<_>>();
        let lengths = lengths_for_frequencies(&frequencies, 1);

        assert!(lengths.iter().all(|&length| length == 10));
    }

    fn kraft_sum_is_one(lengths: &[u8]) -> bool {
        let max_len = lengths.iter().copied().max().unwrap_or(0);
        if max_len == 0 {
            return lengths.iter().all(|&len| len == 0);
        }
        let sum: u64 = lengths
            .iter()
            .filter(|&&len| len != 0)
            .map(|&len| 1u64 << (max_len - len))
            .sum();
        sum == (1u64 << max_len)
    }

    #[test]
    fn single_symbol_table_is_completed_with_a_phantom_code() {
        // A lone used symbol would otherwise get one length-1 code (Kraft 0.5),
        // which strict RAR 5 decoders reject. It must be padded to a complete
        // code without disturbing the used symbol's own length.
        for used in [0usize, 1, 7, 40] {
            let mut frequencies = vec![0usize; 44];
            frequencies[used] = 123;
            let lengths = complete_lengths_for_frequencies(&frequencies, 15);
            assert_eq!(lengths[used], 1, "used symbol {used} keeps a length-1 code");
            assert_eq!(
                lengths.iter().filter(|&&len| len != 0).count(),
                2,
                "exactly one phantom code was added for used symbol {used}"
            );
            assert!(
                kraft_sum_is_one(&lengths),
                "used symbol {used} yields a complete code"
            );
        }
    }

    #[test]
    fn empty_table_stays_empty() {
        let lengths = complete_lengths_for_frequencies(&[0usize; 16], 15);
        assert!(lengths.iter().all(|&len| len == 0));
    }

    #[test]
    fn completed_codes_are_always_complete_for_any_symbol_count() {
        for used_count in 1..=64usize {
            let mut frequencies = vec![0usize; 306];
            for (i, freq) in frequencies.iter_mut().take(used_count).enumerate() {
                *freq = 1 + i; // distinct frequencies, still a valid Huffman input
            }
            let lengths = complete_lengths_for_frequencies(&frequencies, 15);
            assert!(
                kraft_sum_is_one(&lengths),
                "code for {used_count} symbols must be complete"
            );
            assert!(lengths.iter().all(|&len| len <= 15));
        }
    }

    #[test]
    fn multi_symbol_huffman_code_is_left_optimal() {
        // A skewed distribution already yields a complete Huffman code; the
        // completeness pass must not flatten it into a uniform code.
        let frequencies = [100usize, 1, 1, 1, 1];
        let optimal = lengths_for_frequencies(&frequencies, 15);
        let completed = complete_lengths_for_frequencies(&frequencies, 15);
        assert_eq!(optimal, completed);
        assert!(kraft_sum_is_one(&completed));
    }
}
