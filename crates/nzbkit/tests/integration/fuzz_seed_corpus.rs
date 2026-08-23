//! The committed `rar_recovery_scan` seed corpus still reaches the code it
//! was committed to reach.
//!
//! `crates/nzbkit/fuzz/seeds/rar_recovery_scan/` exists because that target's
//! interesting arithmetic sits behind a CRC64 chunk gate and a RAR5 REV
//! header that no mutator guesses: cold it reaches ~226 edges, seeded ~1,686.
//! The failure this file guards is the one `yenc_decode` actually suffered -
//! a corpus that LOOKS seeded but reaches nothing, so a run still prints
//! millions of execs and still says zero crashes while never touching the
//! parser. Nothing about a fuzz corpus is self-checking, and a `.rev` that
//! stopped parsing would be invisible until someone read an edge count.
//!
//! So the named fixtures in that directory are asserted here, by an ordinary
//! `cargo test` that needs neither nightly nor cargo-fuzz. The rest of the
//! directory is fuzzer-derived and deliberately not asserted - a derived blob
//! is allowed to go inert, which is exactly why the real WinRAR output is
//! kept beside it.

use rars::recovery::stream::{MemorySource, scan_inline_recovery_chunks};

/// One seed, and the entry point it has to keep reaching.
const SEEDS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fuzz/seeds/rar_recovery_scan");

fn seed(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(SEEDS).join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("seed {name} is missing: {e}"))
}

/// The REV bomb's own route: a `.rev` header whose slot table is sized by a
/// declared count. Both volumes must still parse AND still verify, because a
/// payload that no longer matches its declared CRC32 is dropped before the
/// planner ever sees it - the seed would be carrying the fuzzer only as far
/// as the checksum.
#[test]
fn the_rev5_seeds_still_parse_and_still_verify() {
    for name in ["multivol_rev.part1.rev", "multivol_rev.part2.rev"] {
        let src = MemorySource(seed(name));
        let volume = rars::rar50::read_rev5_meta(&src)
            .unwrap_or_else(|e| panic!("{name} no longer parses as a RAR5 REV volume: {e}"));
        assert_eq!(
            volume.meta.data_volumes.len(),
            volume.meta.data_count as usize,
            "{name}: slot table and declared count disagree"
        );
        assert!(
            rars::rar50::verify_rev5_payload(&src, &volume).expect("streaming the payload"),
            "{name}: payload no longer matches its declared CRC32"
        );
    }
}

/// The `{RB}` inline scanner is behind a CRC64 over the whole chunk, which is
/// the gate the corpus exists to get past. A seed that stopped yielding a
/// chunk would leave the plan arithmetic unreached.
#[test]
fn the_inline_recovery_seeds_still_yield_a_crc_valid_chunk() {
    for name in ["with_recovery.rar", "with_all_services.rar"] {
        let src = MemorySource(seed(name));
        let scan = scan_inline_recovery_chunks(&src, 1 << 20)
            .unwrap_or_else(|e| panic!("{name} no longer scans for inline recovery: {e}"));
        assert!(
            !scan.chunks.is_empty(),
            "{name}: no `{{RB}}` chunk survives the CRC64 gate any more"
        );
    }
}

/// The legacy RAR 2/3 leg, added with the bounded protect-record repair. Each
/// of these has to still present a record for the target to reach
/// `repair_protect_to_path` at all.
#[test]
fn the_legacy_protect_record_seeds_still_present_a_record() {
    for name in [
        "rar250_protect_head_rr1.rar",
        "with_recovery_rar300.rar",
        "with_compressed_recovery_rar300.rar",
        "with_compressed_recovery_header_synthetic.rar",
    ] {
        let bytes = seed(name);
        let archive = rars::ArchiveReader::read(&bytes)
            .unwrap_or_else(|e| panic!("{name} no longer reads as an archive: {e}"));
        let legacy = archive
            .as_rar15_40()
            .unwrap_or_else(|| panic!("{name} is no longer a RAR 1.5-4.0 archive"));
        let has_record = legacy.protect_records().next().is_some()
            || legacy
                .new_subs()
                .any(|sub| sub.kind == rars::rar15_40::NewSubKind::RecoveryRecord);
        assert!(has_record, "{name}: carries no recovery record any more");
    }
}

/// The whole directory, not just the names above: a seed corpus is only worth
/// its bytes while it stays small enough that nobody is tempted to delete it,
/// and 240 KB was the size this was committed at. The ceiling is generous
/// (2x) so ordinary additions pass and a distillation dumped in whole does
/// not.
#[test]
fn the_seed_corpus_stays_small_enough_to_carry() {
    let mut total = 0u64;
    let mut count = 0usize;
    for entry in std::fs::read_dir(SEEDS).expect("the seed directory exists") {
        let entry = entry.expect("reading the seed directory");
        if entry.file_name() == "README.md" {
            continue;
        }
        total += entry.metadata().expect("seed metadata").len();
        count += 1;
    }
    assert!(
        count > 200,
        "the seed corpus lost most of its inputs: {count}"
    );
    assert!(
        total < 512 * 1024,
        "the seed corpus grew to {total} bytes - distil it with `cargo +nightly fuzz cmin` \
         rather than committing a whole corpus"
    );
}
