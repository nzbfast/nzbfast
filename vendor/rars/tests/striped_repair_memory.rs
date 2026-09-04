//! Does a striped repair actually stay inside its budget?
//!
//! `StripeRepairPlan::working_bytes` is arithmetic; this MEASURES. The
//! whole-grid recovery path holds `data_count * shard_len` resident, and an
//! allocator that hands back address space rather than aborting would let a
//! regression reintroducing that pass every other test in the crate.
//!
//! This lives in its own integration test on purpose. Resident set size is a
//! PROCESS-wide number and cargo runs unit tests as parallel threads inside a
//! single process, so as a unit test it measured every other test's
//! allocations too and failed whenever the suite was busy. Cargo gives each
//! test target its own process, and this target holds exactly one test, so
//! the only thing allocating during the measurement is the repair.
//!
//! test-target-gate: measures the process's own RSS and needs a process
//! holding exactly one test - as a shared-binary test it flaked whenever
//! the suite was busy

use rars::recovery::rar5::{make_encoder_matrix, repair_shards_striped, Gf16, StripeRepairPlan};

const DATA_COUNT: usize = 16;
const SHARD_LEN: usize = 4 << 20;
const GRID: u64 = (DATA_COUNT * SHARD_LEN) as u64;
const BUDGET: u64 = 128 << 10;

#[cfg(unix)]
fn resident_bytes() -> Option<u64> {
    let output = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .ok()?;
    let kib: u64 = String::from_utf8(output.stdout).ok()?.trim().parse().ok()?;
    Some(kib * 1024)
}

#[cfg(not(unix))]
fn resident_bytes() -> Option<u64> {
    None
}

/// Shards generated on demand rather than stored, so the test itself never
/// holds the grid it is checking the repair does not hold. Every shard is one
/// repeated 16-bit symbol, which makes each parity row a single repeated
/// symbol too: real GF math, computable in O(data_count).
fn symbol(index: usize) -> u16 {
    (index as u16) * 7 + 3
}

fn parity_symbol(row: usize) -> u16 {
    let gf = Gf16::new();
    let matrix = make_encoder_matrix(DATA_COUNT, row + 1).unwrap();
    (0..DATA_COUNT).fold(0u16, |sum, index| {
        sum ^ gf.mul(matrix[row][index], symbol(index))
    })
}

fn fill(value: u16, buf: &mut [u8]) {
    for word in buf.chunks_exact_mut(2) {
        word.copy_from_slice(&value.to_le_bytes());
    }
}

#[test]
fn striped_repair_does_not_grow_resident_memory_by_the_grid() {
    let damaged = vec![5usize];
    let rows = vec![0usize];
    let plan = StripeRepairPlan::new(DATA_COUNT, 1, SHARD_LEN, &damaged, &rows).unwrap();
    let stripe = plan.stripe_len_for_budget(BUDGET).unwrap();
    assert!(plan.working_bytes(stripe) <= BUDGET);
    let parity = parity_symbol(0);
    let expected = symbol(5);

    let before = resident_bytes();
    let mut written = 0usize;
    let mut widest = 0usize;
    repair_shards_striped(
        &plan,
        stripe,
        |index, _, buf| {
            widest = widest.max(buf.len());
            fill(symbol(index), buf);
            Ok(())
        },
        |_, _, buf| {
            fill(parity, buf);
            Ok(())
        },
        |_, offset, bytes| {
            // Correctness alongside the memory claim: a repair that allocated
            // nothing because it did nothing must not pass.
            assert!(
                bytes
                    .chunks_exact(2)
                    .all(|w| u16::from_le_bytes([w[0], w[1]]) == expected),
                "rebuilt stripe at {offset} does not match the missing shard"
            );
            written += bytes.len();
            Ok(())
        },
    )
    .unwrap();
    let after = resident_bytes();

    assert_eq!(written, SHARD_LEN, "the whole shard was rebuilt");
    assert!(widest <= stripe, "a callback was handed more than one stripe");

    let (Some(before), Some(after)) = (before, after) else {
        return;
    };
    let grew = after.saturating_sub(before);
    assert!(
        grew < GRID / 4,
        "resident memory grew {grew} bytes repairing a {GRID}-byte grid inside \
         a {BUDGET}-byte budget - the grid is being materialized"
    );

    // Only NOW prove the probe could have seen a grid-sized allocation, so the
    // assertion above is not vacuous. Order matters: the allocator keeps freed
    // pages, so touching this much memory beforehand would let a materialized
    // grid reuse it and move RSS not at all - which is exactly how an earlier
    // version of this test passed while the grid was allocated on purpose.
    let ballast = vec![7u8; GRID as usize];
    std::hint::black_box(&ballast);
    let moved = resident_bytes()
        .map(|now| now.saturating_sub(after) > GRID / 2)
        .unwrap_or(false);
    drop(ballast);
    assert!(
        moved,
        "the RSS probe cannot see a {GRID}-byte allocation, so it cannot \
         police one either"
    );
}
