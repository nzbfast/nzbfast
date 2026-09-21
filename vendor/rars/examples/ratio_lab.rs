//! Compression ratio laboratory. No production CLI behavior is changed.
//! ratio_lab MODE DICTIONARY SOLID OUTPUT INPUT...
//! MODE: baseline, short, adaptive, carry, exhaustive, all, max, store, product,
//! fine, refine, all-fine, all-refine, delta1..delta32, product-auto, wide-auto.
//! Also: region-none (small-block control), region64, region256, region256-split, ultra (complete-archive portfolio).
//! Also: b<KiB>-baseline/refine/all-refine (64..4096; b255 means 262143 bytes).
//! tokenizer-max keeps the smallest complete archive across horizon candidates and old baselines.
//! horizon-adaptive chooses long/short horizons per region, with exact byte costs.
//! opt-baseline, opt-refine, opt-b256-refine, opt-horizon-adaptive use the production optimal parser.
//! opt-horizon-wide adds 1 MiB and 512 KiB choices to opt-horizon-adaptive.
//! opt-horizon-balanced compares 4 MiB and 1 MiB spans with fewer trials.
//! opt-horizon-seven tests every power-of-two span from 64 KiB through 4 MiB.
//! ultimate combines all earlier portfolios and the new horizon choices, testing each named candidate once.
//! opt-delta1..32 and opt-region* combine reversible filters with optimal parsing.
//! optimal-filter-max tests all 32 delta channels and retains no-filter and stored choices; ultimate adds these candidates.
//! ultimate-core retains the preceding 37-candidate portfolio for comparisons.
//! optimal-max compares the optimal combinations and unfiltered fallback archives.
//! tree-opt-refine and tree-opt-horizon-{balanced,wide,seven} use shared per-member tree hints.
//! tree-opt-delta1..32 and tree-opt-region* search transformed data with tree hints.
//! tree-opt-nice32/64/128/256 independently vary the tree comparison cap.
//! tree-refine tests the same hints with the lazy parser; tree-max retains ring horizon controls.
//! ultimate-tree combines tree-max and the complete filter portfolio; tree-member-max adds per-file selection.
//! ultimate-tree-deep adds measured 128/256-byte tree caps; tree-member-deep also selects independent files.
//! ultimate-tree-joint adds joint regional filters and tree search; tree-member-joint adds per-file selection.
//! member-max chooses independent non-solid file blocks across ultimate candidates, retaining the whole-archive winner.
//! RATIO_LAB_CANDIDATES optionally retains each candidate archive for independent verification.
//! SOLID: 0 or 1. Input basenames must be unique; order is preserved.
#[path = "ratio_lab/regions.rs"]
mod regions;
use rars::codec::rar50::ratio::{Encoder, FilteredEncoder, Policy};
use rars::codec::rar50::{EncodeOptions, Rar50FilterKind, Rar50FilterSpec, Rar50Encoder};
use rars::crc32::crc32;
use std::{fs, path::Path, time::Instant};

fn vint(out: &mut Vec<u8>, mut n: u64) {
    while n >= 128 {
        out.push((n as u8 & 127) | 128);
        n >>= 7;
    }
    out.push(n as u8);
}
fn block(out: &mut Vec<u8>, body: &[u8], data: &[u8]) {
    let mut header = Vec::new();
    vint(&mut header, body.len() as u64);
    header.extend(body);
    out.extend(crc32(&header).to_le_bytes());
    out.extend(header);
    out.extend(data);
}
// b<KiB>-<policy>, plus b255 for the exact 262143-byte filter-codec cap.
fn tokenizer_mode(mode: &str) -> Option<(usize, &str)> {
    let (size, policy) = mode.strip_prefix('b')?.split_once('-')?;
    let kib = size.parse::<usize>().ok()?;
    if ![64, 128, 255, 256, 512, 1024, 2048, 4096].contains(&kib)
        || !["baseline", "refine", "all-refine"].contains(&policy)
    {
        return None;
    }
    Some((if kib == 255 { 262143 } else { kib * 1024 }, policy))
}
fn tree_nice_length(mode: &str) -> Option<usize> {
    mode.strip_prefix("tree-opt-nice")?
        .parse::<usize>()
        .ok()
        .filter(|n| [32, 64, 128, 256].contains(n))
}
fn tree_mode(mode: &str) -> bool {
    if tree_nice_length(mode).is_some()
        || mode.strip_prefix("tree-opt-").is_some_and(|base| {
            (base.starts_with("delta") || base.starts_with("region"))
                && optimal_mode(mode.strip_prefix("tree-").unwrap())
        })
    {
        return true;
    }
    mode.strip_prefix("tree-").is_some_and(|base| {
        matches!(
            base,
            "refine"
                | "opt-refine"
                | "opt-horizon-balanced"
                | "opt-horizon-wide"
                | "opt-horizon-seven"
        )
    })
}
fn optimal_mode(mode: &str) -> bool {
    mode.strip_prefix("opt-").is_some_and(|base| {
        [
            "baseline",
            "refine",
            "horizon-adaptive",
            "horizon-wide",
            "horizon-balanced",
            "horizon-seven",
        ]
        .contains(&base)
            || tokenizer_mode(base).is_some_and(|(_, policy)| policy != "all-refine")
            || ["region-none", "region64", "region256", "region256-split"].contains(&base)
            || base
                .strip_prefix("delta")
                .and_then(|n| n.parse::<usize>().ok())
                .is_some_and(|n| (1..=32).contains(&n))
    })
}
fn archive(files: &[(String, Vec<u8>)], dict: usize, solid: bool, mode: &str) -> Vec<u8> {
    let tree = tree_mode(mode);
    let nice_length = tree_nice_length(mode);
    let mode = if nice_length.is_some() {
        "opt-refine"
    } else if tree {
        mode.strip_prefix("tree-").unwrap()
    } else {
        mode
    };
    let optimal = optimal_mode(mode);
    let mode = if optimal {
        mode.strip_prefix("opt-").unwrap()
    } else {
        mode
    };
    let seven_horizon = mode == "horizon-seven";
    let balanced_horizon = mode == "horizon-balanced";
    let wide_horizon = mode == "horizon-wide";
    let adaptive_horizon =
        mode == "horizon-adaptive" || wide_horizon || balanced_horizon || seven_horizon;
    let mode = if adaptive_horizon { "refine" } else { mode };
    let (tokenizer_size, mode) = tokenizer_mode(mode).unwrap_or((4 * 1024 * 1024, mode));
    let policy = Policy {
        short_repeats: matches!(mode, "short" | "all" | "all-fine" | "all-refine"),
        adaptive: matches!(
            mode,
            "adaptive" | "all" | "fine" | "refine" | "all-fine" | "all-refine"
        ),
        carry: matches!(mode, "carry" | "all" | "all-fine" | "all-refine"),
        fine: false,
        refine: false,
        exhaustive: matches!(mode, "exhaustive" | "all" | "all-fine" | "all-refine"),
    };
    let policy = Policy {
        fine: matches!(mode, "fine" | "all-fine"),
        refine: matches!(mode, "refine" | "all-refine"),
        ..policy
    };
    let mut encoder = Encoder::new(dict, policy)
        .with_tokenizer_block_size(tokenizer_size)
        .expect("tokenizer size")
        .with_optimal_parse(optimal)
        .expect("optimal policy")
        .with_tree_search(tree)
        .with_tree_nice_length(nice_length.unwrap_or(64))
        .expect("tree comparison length");
    let filter_options = EncodeOptions::new(256)
        .with_lazy_matching(true)
        .with_max_match_distance(dict)
        .with_optimal_parse(optimal);
    let mut filtered = Rar50Encoder::with_options(filter_options);
    let mut tree_filtered = FilteredEncoder::new(dict, optimal);
    let channels = mode
        .strip_prefix("delta")
        .and_then(|n| n.parse::<usize>().ok());
    let mut out = b"Rar!\x1a\x07\x01\0".to_vec();
    block(&mut out, &[1, 0, if solid { 4 } else { 0 }], &[]);
    for (i, (name, data)) in files.iter().enumerate() {
        let packed = if mode == "store" {
            data.clone()
        } else if mode.starts_with("region") {
            if !solid || i == 0 {
                filtered = Rar50Encoder::with_options(filter_options);
            }
            let span = if mode == "region64" {
                64 * 1024
            } else {
                256 * 1024
            };
            let specs = if mode == "region-none" {
                Vec::new()
            } else {
                regions::select(data, filter_options, span, mode != "region256-split")
            };
            if tree {
                tree_filtered
                    .encode(data, &specs, solid && i != 0)
                    .expect("tree regional encode")
            } else {
                filtered
                    .encode_member_with_filters(data, 0, &specs)
                    .expect("regional encode")
            }
        } else if let Some(channels) = channels {
            if !solid || i == 0 {
                filtered = Rar50Encoder::with_options(filter_options);
            }
            if tree {
                let specs = if data.is_empty() {
                    Vec::new()
                } else {
                    vec![Rar50FilterSpec::new(Rar50FilterKind::Delta { channels })]
                };
                tree_filtered
                    .encode(data, &specs, solid && i != 0)
                    .expect("tree delta encode")
            } else if data.is_empty() {
                filtered.encode_member(data, 0).expect("empty member")
            } else {
                filtered
                    .encode_member_with_filter(
                        data,
                        0,
                        Rar50FilterSpec::new(Rar50FilterKind::Delta { channels }),
                    )
                    .expect("delta encode")
            }
        } else {
            if seven_horizon {
                encoder
                    .encode_seven_horizon(data, solid && i != 0)
                    .expect("seven horizons")
            } else if balanced_horizon {
                encoder
                    .encode_balanced_horizon(data, solid && i != 0)
                    .expect("balanced horizon")
            } else if wide_horizon {
                encoder
                    .encode_wide_horizon(data, solid && i != 0)
                    .expect("wide horizon")
            } else if adaptive_horizon {
                encoder
                    .encode_adaptive_horizon(data, solid && i != 0)
                    .expect("adaptive horizon")
            } else {
                encoder.encode(data, solid && i != 0).expect("encode")
            }
        };
        let mut header = vec![2, 2]; // file header, data present
        vint(&mut header, packed.len() as u64);
        vint(&mut header, 4); // CRC32 present
        vint(&mut header, data.len() as u64);
        vint(&mut header, 0o100644);
        header.extend(crc32(data).to_le_bytes());
        let info = if mode == "store" {
            0
        } else {
            3 << 7
                | ((dict / 131072).trailing_zeros() as u64) << 10
                | if solid && i != 0 { 64 } else { 0 }
        };
        vint(&mut header, info);
        vint(&mut header, 1); // Unix
        vint(&mut header, name.len() as u64);
        header.extend(name.as_bytes());
        block(&mut out, &header, &packed);
    }
    block(&mut out, &[5, 0, 0], &[]);
    out
}
/// Flatten portfolio groups once, preserving their original candidate order.
fn candidate_modes(mode: &str, solid: bool) -> Vec<&str> {
    if mode == "ultimate-tree-joint" {
        let mut modes = candidate_modes("ultimate-tree-deep", solid);
        modes.extend(["tree-opt-region64", "tree-opt-region256-split"]);
        return modes;
    }
    if mode == "tree-member-joint" {
        assert!(
            !solid,
            "member-max requires independently reset non-solid members"
        );
        return candidate_modes("ultimate-tree-joint", false);
    }
    if mode == "ultimate-tree-deep" {
        let mut modes = candidate_modes("ultimate-tree", solid);
        modes.extend(["tree-opt-nice128", "tree-opt-nice256"]);
        return modes;
    }
    if mode == "tree-member-deep" {
        assert!(
            !solid,
            "member-max requires independently reset non-solid members"
        );
        return candidate_modes("ultimate-tree-deep", false);
    }
    if mode == "ultimate-tree" {
        let mut modes = candidate_modes("ultimate", solid);
        for candidate in candidate_modes("tree-max", solid) {
            if !modes.contains(&candidate) {
                modes.push(candidate);
            }
        }
        return modes;
    }
    if mode == "tree-member-max" {
        assert!(
            !solid,
            "member-max requires independently reset non-solid members"
        );
        return candidate_modes("ultimate-tree", false);
    }
    if mode == "tree-max" {
        return vec![
            "opt-horizon-balanced",
            "opt-horizon-wide",
            "opt-horizon-seven",
            "tree-refine",
            "tree-opt-refine",
            "tree-opt-horizon-balanced",
            "tree-opt-horizon-wide",
            "tree-opt-horizon-seven",
            "product-optimal",
        ];
    }
    if mode == "member-max" {
        assert!(
            !solid,
            "member-max requires independently reset non-solid members"
        );
        return candidate_modes("ultimate", false);
    }
    if mode == "optimal-filter-max" {
        let mut modes = vec![
            "store",
            "opt-horizon-seven",
            "opt-region-none",
            "opt-region64",
            "opt-region256",
            "opt-region256-split",
            "opt-delta1",
            "opt-delta2",
            "opt-delta3",
            "opt-delta4",
            "opt-delta5",
            "opt-delta6",
            "opt-delta7",
            "opt-delta8",
            "opt-delta9",
            "opt-delta10",
            "opt-delta11",
            "opt-delta12",
            "opt-delta13",
            "opt-delta14",
            "opt-delta15",
            "opt-delta16",
            "opt-delta17",
            "opt-delta18",
            "opt-delta19",
            "opt-delta20",
            "opt-delta21",
            "opt-delta22",
            "opt-delta23",
            "opt-delta24",
            "opt-delta25",
            "opt-delta26",
            "opt-delta27",
            "opt-delta28",
            "opt-delta29",
            "opt-delta30",
            "opt-delta31",
            "opt-delta32",
        ];
        if !solid {
            modes.push("product-optimal-auto");
        }
        return modes;
    }
    if mode == "ultimate" || mode == "ultimate-core" {
        let mut modes = Vec::new();
        let groups = ["ultra", "optimal-max", "tokenizer-max"];
        for group in groups {
            for candidate in candidate_modes(group, solid) {
                if !modes.contains(&candidate) {
                    modes.push(candidate);
                }
            }
        }
        for candidate in [
            "opt-horizon-wide",
            "opt-horizon-balanced",
            "opt-horizon-seven",
        ] {
            if !modes.contains(&candidate) {
                modes.push(candidate);
            }
        }
        if mode == "ultimate" {
            for candidate in candidate_modes("optimal-filter-max", solid) {
                if !modes.contains(&candidate) {
                    modes.push(candidate);
                }
            }
        }
        return modes;
    }
    let modes: &[&str] = if mode == "optimal-max" {
        &[
            "baseline",
            "refine",
            "all-refine",
            "store",
            "product-optimal",
            "opt-baseline",
            "opt-refine",
            "opt-b256-refine",
            "opt-horizon-adaptive",
        ]
    } else if mode == "tokenizer-max" {
        &[
            "baseline",
            "refine",
            "all-refine",
            "store",
            "b64-refine",
            "b128-refine",
            "b255-baseline",
            "b256-refine",
            "b256-all-refine",
            "b512-refine",
            "b1024-refine",
            "b2048-refine",
            "horizon-adaptive",
        ]
    } else if mode == "ultra" {
        if solid {
            &[
                "product",
                "baseline",
                "short",
                "adaptive",
                "carry",
                "exhaustive",
                "all",
                "fine",
                "refine",
                "all-fine",
                "all-refine",
                "store",
                "delta8",
                "delta16",
                "delta24",
                "delta32",
                "region-none",
                "region64",
                "region256",
                "region256-split",
            ]
        } else {
            &[
                "product-auto",
                "baseline",
                "short",
                "adaptive",
                "carry",
                "exhaustive",
                "all",
                "fine",
                "refine",
                "all-fine",
                "all-refine",
                "store",
                "delta8",
                "delta16",
                "delta24",
                "delta32",
                "region-none",
                "region64",
                "region256",
                "region256-split",
            ]
        }
    } else if mode == "wide-auto" {
        // The production writer rejects AutoSize for solid sets. Retain
        // its unfiltered solid arm instead; the explicit codec arms below
        // carry filtered LZ history across members and are tested separately.
        if solid {
            &["product", "delta8", "delta16", "delta24", "delta32"]
        } else {
            &["product-auto", "delta8", "delta16", "delta24", "delta32"]
        }
    } else if mode == "max" {
        &[
            "baseline",
            "short",
            "adaptive",
            "carry",
            "exhaustive",
            "all",
            "fine",
            "refine",
            "all-fine",
            "all-refine",
            "store",
        ]
    } else {
        &[mode]
    };
    modes.to_vec()
}

/// A horizon cannot affect tokenization when every member fits one chunk.
/// This also preserves solid history and carried state: each member has the
/// same single parse, emitter invocation and final state as its base policy.
fn candidate_identity(mode: &str, largest_member: usize) -> String {
    let (tree, mode) = mode
        .strip_prefix("tree-")
        .map_or(("", mode), |base| ("tree-", base));
    let (prefix, base) = mode
        .strip_prefix("opt-")
        .map_or(("", mode), |base| ("opt-", base));
    let single = tokenizer_mode(base).or(match base {
        "horizon-adaptive" | "horizon-wide" => Some((256 * 1024, "refine")),
        "horizon-balanced" => Some((1024 * 1024, "refine")),
        "horizon-seven" => Some((64 * 1024, "refine")),
        _ => None,
    });
    if let Some((size, policy)) = single {
        if largest_member <= size {
            return format!("{tree}{prefix}{policy}");
        }
    }
    format!("{tree}{mode}")
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert!(
        args.len() >= 6,
        "ratio_lab MODE DICTIONARY SOLID OUTPUT INPUT..."
    );
    let mode = &args[1];
    let delta_channels = mode
        .strip_prefix("delta")
        .and_then(|n| n.parse::<usize>().ok());
    assert!(
        [
            "baseline",
            "short",
            "adaptive",
            "carry",
            "exhaustive",
            "all",
            "max",
            "wide-auto",
            "region-none",
            "region64",
            "region256",
            "region256-split",
            "ultra",
            "ultimate",
            "ultimate-core",
            "member-max",
            "tree-max",
            "ultimate-tree",
            "tree-member-max",
            "ultimate-tree-deep",
            "tree-member-deep",
            "ultimate-tree-joint",
            "tree-member-joint",
            "optimal-filter-max",
            "tokenizer-max",
            "optimal-max",
            "horizon-adaptive",
            "store",
            "product",
            "product-auto",
            "product-optimal",
            "product-optimal-auto",
            "fine",
            "refine",
            "all-fine",
            "all-refine"
        ]
        .contains(&mode.as_str())
            || optimal_mode(mode)
            || tree_mode(mode)
            || tokenizer_mode(mode).is_some()
            || delta_channels.is_some_and(|n| (1..=32).contains(&n))
    );
    let dict: usize = args[2].parse().unwrap();
    assert!((131072..=1u64 << 32).contains(&(dict as u64)) && dict.is_power_of_two());
    assert!(args[3] == "0" || args[3] == "1");
    let solid = args[3] == "1";
    assert!(
        !matches!(
            mode.as_str(),
            "member-max" | "tree-member-max" | "tree-member-deep" | "tree-member-joint"
        ) || !solid,
        "member-max does not support solid archives"
    );
    let files: Vec<_> = args[5..]
        .iter()
        .map(|p| {
            (
                Path::new(p)
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_owned(),
                fs::read(p).unwrap(),
            )
        })
        .collect();
    let mut names = std::collections::HashSet::new();
    assert!(
        files.iter().all(|(name, _)| names.insert(name)),
        "duplicate basenames"
    );
    let candidate_dir = std::env::var_os("RATIO_LAB_CANDIDATES").map(std::path::PathBuf::from);
    if let Some(dir) = &candidate_dir {
        fs::create_dir_all(dir).expect("candidate evidence directory");
    }
    let start = Instant::now();
    let modes = candidate_modes(mode, solid);
    let largest_member = files.iter().map(|(_, data)| data.len()).max().unwrap_or(0);
    let identities: Vec<_> = modes
        .iter()
        .map(|mode| candidate_identity(mode, largest_member))
        .collect();
    let mut equivalent: std::collections::HashMap<String, (String, Vec<u8>)> =
        std::collections::HashMap::new();
    let mut best: Option<Vec<u8>> = None;
    let mut winner = "";
    let mut member_best: Vec<Option<Vec<u8>>> = vec![None; files.len()];
    let mut member_winners = vec![""; files.len()];
    for (candidate_index, &candidate) in modes.iter().enumerate() {
        let identity = &identities[candidate_index];
        let packed = if let Some((prior, bytes)) = equivalent.get(identity) {
            eprintln!("equivalent={candidate} cached_from={prior}");
            bytes.clone()
        } else if candidate == "product"
            || candidate == "product-auto"
            || candidate == "product-optimal"
            || candidate == "product-optimal-auto"
        {
            use rars::rar50::{CompressedEntry, Rar50Writer, WriterOptions};
            let mut features = rars::FeatureSet::default();
            features.solid = solid;
            let entries: Vec<_> = files
                .iter()
                .map(|(name, data)| CompressedEntry {
                    name: name.as_bytes(),
                    data,
                    attributes: 0o100644,
                    mtime: None,
                    host_os: 1,
                })
                .collect();
            Rar50Writer::new(
                WriterOptions::new(rars::ArchiveVersion::Rar50, features)
                    .with_dictionary_size(dict as u64)
                    .with_optimal_parse(candidate.starts_with("product-optimal")),
            )
            .filter_policy(
                if matches!(candidate, "product-auto" | "product-optimal-auto") {
                    rars::rar50::FilterPolicy::AutoSize
                } else {
                    rars::rar50::FilterPolicy::None
                },
            )
            .compressed_entries(&entries)
            .finish()
            .unwrap()
        } else {
            archive(&files, dict, solid, candidate)
        };
        // Retain only identities that occur again, and only for short-member
        // equivalences. Large-file portfolios do not acquire a cache of archives.
        if identities[candidate_index + 1..].contains(identity)
            && !equivalent.contains_key(identity)
        {
            equivalent.insert(identity.clone(), (candidate.to_owned(), packed.clone()));
        }
        if matches!(
            mode.as_str(),
            "member-max" | "tree-member-max" | "tree-member-deep" | "tree-member-joint"
        ) {
            // Parse our own validated-format candidate rather than guessing header sizes.
            // Non-solid file blocks carry no dictionary/repeat/filter state between files.
            let parsed = rars::rar50::Archive::parse(&packed).expect("candidate headers");
            assert_eq!(parsed.sfx_offset, 0);
            let mut index = 0;
            for entry in &parsed.blocks {
                match entry {
                    rars::rar50::Block::File(header) => {
                        assert!(index < files.len());
                        assert_eq!(header.name, files[index].0.as_bytes());
                        assert_eq!(header.unpacked_size as usize, files[index].1.len());
                        assert_eq!(header.compression_info & 64, 0, "solid dependency");
                        assert!(!header.encrypted && header.redirection.is_none());
                        let bytes = &packed[header.block.offset..header.block.data_range.end];
                        if member_best[index]
                            .as_ref()
                            .is_none_or(|best| bytes.len() < best.len())
                        {
                            member_best[index] = Some(bytes.to_vec());
                            member_winners[index] = candidate;
                        }
                        index += 1;
                    }
                    rars::rar50::Block::End(_) => {}
                    _ => panic!("member-max only accepts ordinary file candidates"),
                }
            }
            assert_eq!(index, files.len());
        }
        if let Some(dir) = &candidate_dir {
            fs::write(dir.join(format!("{candidate}.rar")), &packed)
                .expect("candidate evidence archive");
        }
        eprintln!("candidate={candidate} bytes={}", packed.len());
        if best.as_ref().is_none_or(|b| packed.len() < b.len()) {
            best = Some(packed);
            winner = candidate;
        }
    }
    if matches!(
        mode.as_str(),
        "member-max" | "tree-member-max" | "tree-member-deep" | "tree-member-joint"
    ) {
        let mut mixed = b"Rar!\x1a\x07\x01\0".to_vec();
        block(&mut mixed, &[1, 0, 0], &[]);
        for (index, bytes) in member_best.into_iter().enumerate() {
            let bytes = bytes.expect("each member has a candidate");
            eprintln!(
                "member={index} winner={} block_bytes={}",
                member_winners[index],
                bytes.len()
            );
            mixed.extend(bytes);
        }
        block(&mut mixed, &[5, 0, 0], &[]);
        if let Some(dir) = &candidate_dir {
            fs::write(dir.join("member-mix.rar"), &mixed).expect("member evidence archive");
        }
        eprintln!("candidate=member-mix bytes={}", mixed.len());
        if best.as_ref().is_none_or(|b| mixed.len() < b.len()) {
            best = Some(mixed);
            winner = "member-mix";
        }
    }
    let best = best.unwrap();
    let seconds = start.elapsed().as_secs_f64();
    fs::write(&args[4], &best).unwrap();
    println!(
        "mode={mode} winner={winner} bytes={} encode_seconds={seconds:.6}",
        best.len()
    );
}
