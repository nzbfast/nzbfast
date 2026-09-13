//! A thin command line over the RAR 5 writer, for timing archive CREATION
//! against `rar a` on equal terms. Not a product: the product creates
//! archives through `postfast` and the posting tool, which drive the same
//! writer. Inputs are read into memory whole, as the writer takes slices.
//!
//! Usage: rar5cli a [-m0|-m3] [-mo] [-mh] [-md<bytes>] [-v<bytes>] [-p<pw>] [-hp<pw>]
//!                  [-htb] [-s] [-rr<percent>] [-seed<n>] [--stream]
//!                  [--fixed-entropy-blocks] <archive.rar> <file>...
//!
//! `-v` writes `<stem>.part01.rar`, `.part02.rar`, ... like rar's own
//! numbering; without it a single `<archive.rar>`. `-p` encrypts the data,
//! `-hp` the headers too. `--stream` (`-m0` optionally with `-p`/`-hp`, or
//! `-m3` plain; no record, no solid) writes through the streamed writers: each input is read
//! twice, once for its CRC and once as it is copied to the output, and
//! nothing is held. `-htb` adds the BLAKE2sp hash record (rar's
//! `-htb`); the default is CRC32 only, as rar's is. `-s` makes a solid
//! archive (single volume only). `-rr<percent>` adds a recovery record
//! (rar's `-rr`). `-m3` here means the writer's default
//! level (256 candidates, lazy matching); `-m0` stores. `-mo` swaps the
//! lazy parser for the cost-based one (`WriterOptions::optimal_parse`).
//! `--fixed-entropy-blocks` cuts the entropy blocks every 256 KiB of input
//! instead of where the exact encoded cost says to, which is the A/B arm
//! for measuring the boundary search (nzbfast-local change, 7 Sep 2026).
//! `-mf` sets `FilterPolicy::Sampled` (sample-guided regional filters;
//! compressed, not solid, single archive or volumes) - the writer's default is no
//! filter at all, and this is the arm that prices the policy.
use rars::rar50::{
    CompressedEntry, EncryptedCompressedEntry, EncryptedStoredEntry, FilterPolicy, HashRecord,
    Rar50VolumeWriter, Rar50Writer, StoredEntry, WriterOptions,
};
use rars::{ArchiveVersion, FeatureSet};
use std::path::Path;

fn main() {
    assert!(
        cfg!(feature = "ratio-lab")
            || (std::env::var_os("RARS_TREE_SAMPLE_STRIDE").is_none()
                && std::env::var_os("RARS_TREE_CHAIN_DEPTH").is_none()
                && std::env::var_os("RARS_TREE_HASH8").is_none()
                && std::env::var_os("RARS_TREE_HASH8_SLOTS").is_none()
                && std::env::var_os("RARS_TREE_CUT").is_none()
                && std::env::var_os("RARS_TREE_MULTI_HASH").is_none()),
        "RARS_TREE_* research controls require --features ratio-lab"
    );
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 || args[1] != "a" {
        eprintln!("usage: rar5cli a [-m0|-m3] [-mo] [-mh] [-md<bytes>] [-v<bytes>] [-p<pw>] [-hp<pw>] [-htb] [-s] [-rr<percent>] <archive.rar> <file>...");
        std::process::exit(2);
    }
    let mut store = false;
    let mut optimal_parse = false;
    let mut tokenizer_horizon_choice = false;
    let mut dictionary: Option<u64> = None;
    let mut volume: Option<usize> = None;
    let mut password: Option<Vec<u8>> = None;
    let mut header_encryption = false;
    let mut hash = HashRecord::Crc32Only;
    let mut solid = false;
    let mut recovery: Option<u64> = None;
    let mut seed: Option<u64> = None;
    let mut stream = false;
    let mut adaptive_entropy_blocks = true;
    let mut sampled_filters = false;
    let mut positional = Vec::new();
    for arg in &args[2..] {
        if let Some(rest) = arg.strip_prefix("-md") {
            dictionary = Some(rest.parse().expect("-md<bytes>"));
        } else if arg == "-m0" {
            store = true;
        } else if arg == "-m3" {
            store = false;
        } else if arg == "-mo" {
            optimal_parse = true;
        } else if arg == "-mh" {
            tokenizer_horizon_choice = true;
        } else if let Some(rest) = arg.strip_prefix("-v") {
            volume = Some(rest.parse().expect("-v<bytes>"));
        } else if let Some(rest) = arg.strip_prefix("-hp") {
            password = Some(rest.as_bytes().to_vec());
            header_encryption = true;
        } else if let Some(rest) = arg.strip_prefix("-p") {
            password = Some(rest.as_bytes().to_vec());
        } else if arg == "-htb" {
            hash = HashRecord::Blake2sp;
        } else if arg == "-s" {
            solid = true;
        } else if let Some(rest) = arg.strip_prefix("-rr") {
            recovery = Some(rest.parse().expect("-rr<percent>"));
        } else if let Some(rest) = arg.strip_prefix("-seed") {
            seed = Some(rest.parse().expect("-seed<n>"));
        } else if arg == "--stream" {
            stream = true;
        } else if arg == "--fixed-entropy-blocks" {
            adaptive_entropy_blocks = false;
        } else if arg == "-mf" {
            sampled_filters = true;
        } else {
            positional.push(arg.clone());
        }
    }
    let (archive, files) = positional.split_first().expect("archive and files");
    if stream {
        assert!(
            !solid && (store || password.is_none()) && (recovery.is_none() || (store && password.is_none())),
            "--stream is -m0 (optionally -p/-hp, or -rr) or -m3 (plain)"
        );
        let mut features = FeatureSet::default();
        features.file_encryption = password.is_some();
        features.header_encryption = header_encryption;
        features.recovery_record = recovery.is_some();
        let mut options =
            WriterOptions::new(ArchiveVersion::Rar50, features)
                .with_hash_record(hash)
                .with_optimal_parse(optimal_parse)
                .with_adaptive_entropy_blocks(adaptive_entropy_blocks)
                .with_tokenizer_horizon_choice(tokenizer_horizon_choice);
        if store {
            options = options.with_compression_level(0);
        }
        if let Some(dictionary) = dictionary {
            options = options.with_dictionary_size(dictionary);
        }
        if let Some(seed) = seed {
            let mut bytes = [0u8; 32];
            for (chunk, byte) in bytes
                .chunks_mut(8)
                .zip(std::iter::repeat(seed.to_le_bytes()))
            {
                chunk.copy_from_slice(&byte);
            }
            options = options.with_entropy(rars::Entropy::Seeded(bytes));
        }
        use std::io::{BufWriter, Seek, SeekFrom};
        let mut entries = Vec::new();
        let names: Vec<String> = files
            .iter()
            .map(|f| {
                Path::new(f)
                    .file_name()
                    .expect("file name")
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        for (f, name) in files.iter().zip(&names) {
            let mut file = std::fs::File::open(f).expect("open input");
            let (size, crc) = rars::rar50::crc32_of_reader(&mut file).expect("crc pass");
            file.seek(SeekFrom::Start(0)).expect("rewind");
            entries.push(rars::rar50::StreamedStoredEntry {
                name: name.as_bytes(),
                mtime: None,
                attributes: 0,
                host_os: 3,
                size,
                crc32: crc,
                source: file,
            });
        }
        let pw = password.clone();
        let (count, total) = match (volume, pw) {
            (Some(size), None) => {
                let stem = archive.strip_suffix(".rar").unwrap_or(archive).to_string();
                let open = |index: u64| {
                    std::fs::File::create(format!("{stem}.part{:02}.rar", index + 1))
                        .map(|f| BufWriter::with_capacity(1 << 20, f))
                };
                let sizes = if store {
                    rars::rar50::write_stored_volumes_streamed_with_recovery(
                        options,
                        recovery,
                        size,
                        &mut entries,
                        open,
                    )
                } else {
                    rars::rar50::write_compressed_volumes_streamed(
                        options,
                        size,
                        &mut entries,
                        open,
                    )
                }
                .expect("write volumes");
                (sizes.len(), sizes.iter().sum::<u64>())
            }
            (Some(size), Some(pw)) => {
                let stem = archive.strip_suffix(".rar").unwrap_or(archive).to_string();
                let sizes = rars::rar50::write_encrypted_stored_volumes_streamed(
                    options,
                    &pw,
                    size,
                    &mut entries,
                    |index| {
                        std::fs::File::create(format!("{stem}.part{:02}.rar", index + 1))
                            .map(|f| BufWriter::with_capacity(1 << 20, f))
                    },
                )
                .expect("write volumes");
                (sizes.len(), sizes.iter().sum::<u64>())
            }
            (None, None) => {
                let mut sink = BufWriter::with_capacity(
                    1 << 20,
                    std::fs::File::create(archive).expect("create output"),
                );
                let total = if store {
                    rars::rar50::write_stored_archive_streamed_with_recovery(
                        options,
                        recovery,
                        &mut entries,
                        &mut sink,
                    )
                } else {
                    rars::rar50::write_compressed_archive_streamed(
                        options,
                        &mut entries,
                        &mut sink,
                    )
                }
                .expect("write archive");
                (1, total)
            }
            (None, Some(pw)) => {
                let mut sink = BufWriter::with_capacity(
                    1 << 20,
                    std::fs::File::create(archive).expect("create output"),
                );
                let total = rars::rar50::write_encrypted_stored_archive_streamed(
                    options,
                    &pw,
                    &mut entries,
                    &mut sink,
                )
                .expect("write archive");
                (1, total)
            }
        };
        println!("volumes={count} bytes={total}");
        return;
    }
    let datas: Vec<(String, Vec<u8>)> = files
        .iter()
        .map(|f| {
            let name = Path::new(f)
                .file_name()
                .expect("file name")
                .to_string_lossy()
                .into_owned();
            (name, std::fs::read(f).expect("read input"))
        })
        .collect();

    let mut features = FeatureSet::default();
    features.solid = solid;
    features.file_encryption = password.is_some();
    features.header_encryption = header_encryption;
    features.recovery_record = recovery.is_some();
    let mut options = WriterOptions::new(ArchiveVersion::Rar50, features)
        .with_hash_record(hash)
        .with_optimal_parse(optimal_parse)
        .with_adaptive_entropy_blocks(adaptive_entropy_blocks)
        .with_tokenizer_horizon_choice(tokenizer_horizon_choice);
    if let Some(dictionary) = dictionary {
        options = options.with_dictionary_size(dictionary);
    }
    if let Some(seed) = seed {
        // Seeded entropy: salts and IVs from a fixed sequence, so two
        // builds can be compared byte for byte.
        let mut bytes = [0u8; 32];
        for (chunk, byte) in bytes
            .chunks_mut(8)
            .zip(std::iter::repeat(seed.to_le_bytes()))
        {
            chunk.copy_from_slice(&byte);
        }
        options = options.with_entropy(rars::Entropy::Seeded(bytes));
    }
    if store {
        options = options.with_compression_level(0);
    }

    let stored: Vec<StoredEntry> = datas
        .iter()
        .map(|(n, d)| StoredEntry {
            name: n.as_bytes(),
            data: d,
            mtime: None,
            attributes: 0,
            host_os: 3,
        })
        .collect();
    let compressed: Vec<CompressedEntry> = datas
        .iter()
        .map(|(n, d)| CompressedEntry {
            name: n.as_bytes(),
            data: d,
            mtime: None,
            attributes: 0,
            host_os: 3,
        })
        .collect();
    let pw = password.clone().unwrap_or_default();
    let enc_stored: Vec<EncryptedStoredEntry> = datas
        .iter()
        .map(|(n, d)| EncryptedStoredEntry {
            name: n.as_bytes(),
            data: d,
            mtime: None,
            attributes: 0,
            host_os: 3,
            password: &pw,
        })
        .collect();
    let enc_compressed: Vec<EncryptedCompressedEntry> = datas
        .iter()
        .map(|(n, d)| EncryptedCompressedEntry {
            name: n.as_bytes(),
            data: d,
            mtime: None,
            attributes: 0,
            host_os: 3,
            password: &pw,
        })
        .collect();

    let volumes: Vec<Vec<u8>> = match volume {
        Some(size) => {
            let w = Rar50VolumeWriter::new(options)
                .max_payload_per_volume(size)
                .recovery_percent(recovery);
            let w = if sampled_filters {
                assert!(!store && !solid, "-mf is a compressed, non-solid archive");
                w.filter_policy(FilterPolicy::Sampled)
            } else {
                w
            };
            let w = match (store, password.is_some()) {
                (true, false) => w.stored_entries(&stored),
                (false, false) => w.compressed_entries(&compressed),
                (true, true) => w.encrypted_stored_entries(&enc_stored),
                (false, true) => w.encrypted_compressed_entries(&enc_compressed),
            };
            w.finish().expect("write volumes")
        }
        None => {
            let w = Rar50Writer::new(options).recovery_percent(recovery);
            let w = if sampled_filters {
                assert!(!store && !solid, "-mf is a compressed, non-solid archive");
                w.filter_policy(FilterPolicy::Sampled)
            } else {
                w
            };
            let w = match (store, password.is_some()) {
                (true, false) => w.stored_entries(&stored),
                (false, false) => w.compressed_entries(&compressed),
                (true, true) => w.encrypted_stored_entries(&enc_stored),
                (false, true) => w.encrypted_compressed_entries(&enc_compressed),
            };
            vec![w.finish().expect("write archive")]
        }
    };
    if volumes.len() == 1 && volume.is_none() {
        std::fs::write(archive, &volumes[0]).expect("write output");
    } else {
        let stem = archive.strip_suffix(".rar").unwrap_or(archive);
        for (index, bytes) in volumes.iter().enumerate() {
            std::fs::write(format!("{stem}.part{:02}.rar", index + 1), bytes)
                .expect("write volume");
        }
    }
    let total: usize = volumes.iter().map(Vec::len).sum();
    println!("volumes={} bytes={total}", volumes.len());
    // The ring probe's stage counters, when the research build asked for
    // them (nzbfast-local change, 8 Sep 2026).
    #[cfg(feature = "ratio-lab")]
    if std::env::var_os("RARS_PROBE_STATS").is_some() {
        eprint!("{}", rars::codec::rar50::probe_stats::report());
    }
}
