//! The nested password-chain auto-unlock cases and their
//! harvest/resolve pins: a 3-level encrypted chain opened from one
//! on-disk password, the loud park when no candidate matches, the
//! harvest cap and its sources, and the provided password kept when it
//! already works.
//!
//! Its own file rather than a block in `repair_tests.rs`, which sat at
//! 2,909 lines of the size gate's 3,000-line ceiling when this subject
//! came out - the same reason `ladder_tests`, `side_fetch_tests`,
//! `unpackprog_tests`, `vol_affinity_tests` and `shortfall_gate_tests`
//! are each out here. A pure move: every case and helper below is
//! byte-identical to the block `repair_tests.rs` carried.

use super::*;

// -- nested password-chain auto-unlock -------------------------------

fn chain_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("nzbfast-pwchain-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A single non-volume RAR5 store archive holding `files`, each its own
/// AES stream under one shared `pw` - the real multi-file encrypted
/// store shape (`rar -m0 -p`).
fn enc_store(pw: &str, files: &[(&str, &[u8])], seed: u8) -> Vec<u8> {
    use nzbkit::rar::fixtures;
    let encs: Vec<fixtures::EncFile> = files
        .iter()
        .enumerate()
        .map(|(i, (_, b))| fixtures::encrypt_file(pw, b, seed.wrapping_add((i as u8) * 7 + 1)))
        .collect();
    let pieces: Vec<(&str, &fixtures::EncFile, std::ops::Range<usize>, bool, bool)> = files
        .iter()
        .zip(&encs)
        .map(|((name, _), f)| (*name, f, 0..f.cipher.len(), false, false))
        .collect();
    fixtures::rar5_volume_enc(&pieces, None)
}

/// Recursively find the first file named `name` under `dir`.
fn find_file(dir: &std::path::Path, name: &str) -> Option<PathBuf> {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                stack.push(p);
            } else if p.file_name().is_some_and(|n| n == name) {
                return Some(p);
            }
        }
    }
    None
}

/// The gauntlet: a 3-level encrypted chain where each level carries the
/// NEXT level's password in a sibling text file. From only the outermost
/// password on disk, the whole stack auto-extracts with zero manual
/// unlocks and byte-exact final output.
#[test]
fn password_chain_auto_unlocks_three_levels() {
    let dir = chain_dir("unlock");
    let payload: Vec<u8> = (0..120_000u32)
        .map(|i| (i as u8).wrapping_mul(53).wrapping_add(9))
        .collect();
    // Innermost first, then wrap outward.
    let stage3 = enc_store("charlie", &[("movie.mkv", &payload)], 40);
    let stage2 = enc_store(
        "bravo",
        &[("stage3.rar", &stage3), ("pw3.txt", b"charlie\n")],
        20,
    );
    let stage1 = enc_store(
        "alpha",
        &[("stage2.rar", &stage2), ("pw2.txt", b"bravo\n")],
        10,
    );
    // On disk, as if the level above had just produced them.
    std::fs::write(dir.join("stage1.rar"), &stage1).unwrap();
    std::fs::write(dir.join("pw1.txt"), b"alpha\n").unwrap();

    // No job password: every level's key must come from the chain.
    let ok = extract_nested(&dir, None, 0).expect("extract_nested");
    assert!(
        ok.produced(),
        "3-level password chain must auto-extract (rc=0), zero parks"
    );

    let found = find_file(&dir, "movie.mkv").expect("final payload produced");
    assert_eq!(
        std::fs::read(&found).unwrap(),
        payload,
        "payload bytes differ"
    );

    // A clean nest leaves ONLY the final payload plus the extracted
    // siblings the chain rode in on (the password notes) - the spent
    // intermediate archives must not litter the output dir.
    assert!(
        find_file(&dir, "stage2.rar").is_none(),
        "consumed intermediate stage2.rar must be swept"
    );
    assert!(
        find_file(&dir, "stage3.rar").is_none(),
        "consumed intermediate stage3.rar must be swept"
    );
    // Legitimately-extracted siblings survive the sweep.
    assert!(
        find_file(&dir, "pw2.txt").is_some(),
        "extracted sibling pw2.txt kept"
    );
    assert!(
        find_file(&dir, "pw3.txt").is_some(),
        "extracted sibling pw3.txt kept"
    );
    // The outer downloaded archive (in `before`, not produced by the
    // nest) is out of scope for this sweep - stage1.rar is the ONLY
    // archive that may remain.
    let leftover_archives: Vec<String> = {
        let mut v = Vec::new();
        let mut stack = vec![dir.clone()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                let p = e.path();
                if e.file_type().is_ok_and(|t| t.is_dir()) {
                    stack.push(p);
                } else if p.extension().is_some_and(|x| {
                    let x = x.to_ascii_lowercase();
                    x == "rar" || x == "7z"
                }) {
                    v.push(p.file_name().unwrap().to_string_lossy().into_owned());
                }
            }
        }
        v.sort();
        v
    };
    assert_eq!(
        leftover_archives,
        vec!["stage1.rar".to_string()],
        "only the outer downloaded archive may remain, got {leftover_archives:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Negative: when no harvested candidate matches, the level fails loudly
/// (rc=1 -> the daemon parks for a manual 🔑) exactly as before this
/// feature, and never writes garbage output.
#[test]
fn password_chain_parks_when_no_candidate_matches() {
    let dir = chain_dir("nomatch");
    let payload = vec![0x5au8; 48_000];
    let locked = enc_store("password-not-on-disk", &[("movie.mkv", &payload)], 12);
    std::fs::write(dir.join("stage1.rar"), &locked).unwrap();
    // A decoy sidecar that does not contain the password.
    std::fs::write(
        dir.join("readme.nfo"),
        b"enjoy the release\nripped by nobody\n",
    )
    .unwrap();

    let ok = extract_nested(&dir, None, 0).expect("extract_nested");
    assert_eq!(
        ok,
        NestOutcome::Failed,
        "unmatched password must fail loudly, not exit 0"
    );
    // The extractor may create-then-abort an output file on a wrong
    // password, but it must never yield the real plaintext (rc=1 tells
    // the daemon to park and keep the volumes for a manual 🔑).
    if let Some(p) = find_file(&dir, "movie.mkv") {
        assert_ne!(
            std::fs::read(&p).unwrap(),
            payload,
            "must not decrypt without the key"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// `nested_chain_deeper_than_cap_materializes_rc0` MOVED, rewritten, to
// `crates/nzbfast-unpack/src/unpack/nested_depth_tests.rs` on 31 Aug 2026. It
// drove a 6-deep STORE chain and asserted the payload was NOT produced,
// which stopped being the truth the moment the disk site stopped
// charging stored layers against the depth cap - and the fact that it
// still PASSED after `c0b1c788a` is how that commit found it was
// changing only one of the two sites that enforce the cap. Everything it
// asserted is asserted there: rc=0 on a chain past the cap, the deepest
// layer left materialized byte-exact, and the payload absent - now on a
// ladder where the cap really binds, beside the store ladder that must
// run past it. Nothing here is about the depth cap any more.

/// Harvest is bounded: a sidecar with far more lines than the cap yields
/// at most MAX_PW_CANDIDATES candidates, and the job password leads.
#[test]
fn harvest_password_candidate_cap() {
    let dir = chain_dir("cap");
    let mut big = String::new();
    for i in 0..500 {
        big.push_str(&format!("candidate-{i}\n"));
    }
    std::fs::write(dir.join("list.txt"), big).unwrap();
    let cands = harvest_password_candidates(&dir, Some("job-pw"));
    assert!(
        cands.len() <= MAX_PW_CANDIDATES,
        "harvest exceeded cap: {}",
        cands.len()
    );
    assert_eq!(cands[0].value, "job-pw");
    assert_eq!(cands[0].source, "job password");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Harvest reads sidecar lines (raw AND label-stripped), dedupes, and
/// includes the release/sibling stems.
#[test]
fn harvest_reads_lines_labels_and_stems() {
    let dir = chain_dir("harvest");
    std::fs::write(dir.join("password.txt"), b"Password: hunter2\n").unwrap();
    std::fs::write(
        dir.join("The.Release.Name.rar"),
        b"Rar!\x1a\x07\x01\x00junk",
    )
    .unwrap();
    // Oversized sidecar is ignored (payload, not a hint).
    std::fs::write(
        dir.join("big.txt"),
        vec![b'x'; (PW_SIDECAR_MAX + 1) as usize],
    )
    .unwrap();
    let cands = harvest_password_candidates(&dir, None);
    let vals: Vec<&str> = cands.iter().map(|c| c.value.as_str()).collect();
    assert!(vals.contains(&"Password: hunter2"), "raw line: {vals:?}");
    assert!(vals.contains(&"hunter2"), "label-stripped value: {vals:?}");
    assert!(
        cands.iter().any(|c| c.source == "release/sibling stem"),
        "stems harvested: {vals:?}"
    );
    assert!(
        !vals.iter().any(|v| v.starts_with("xxxx")),
        "oversized sidecar must be skipped"
    );
    let mut uniq = vals.clone();
    uniq.sort_unstable();
    uniq.dedup();
    assert_eq!(uniq.len(), vals.len(), "candidates must be deduped");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The provided password, when it already works, is kept as-is: no
/// harvest, no override.
#[test]
fn resolve_keeps_working_provided_password() {
    let dir = chain_dir("provided");
    let vol = enc_store("rightpw", &[("a.bin", b"data bytes")], 30);
    std::fs::write(dir.join("s.rar"), &vol).unwrap();
    assert_eq!(resolve_level_password(&dir, Some("rightpw")), None);
    // A wrong provided password with a matching sidecar gets corrected.
    std::fs::write(dir.join("key.txt"), b"rightpw\n").unwrap();
    assert_eq!(
        resolve_level_password(&dir, Some("wrongpw")).as_deref(),
        Some("rightpw")
    );
    let _ = std::fs::remove_dir_all(&dir);
}
