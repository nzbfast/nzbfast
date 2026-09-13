//! Usage: bench_rar5_create INPUT BYTES ROUNDS [lz|literal|archive|store|encrypted|headers] [OUTPUT]
//! With --features parallel,ratio-lab: --writer-memory DICTIONARY OUTPUT INPUT... [--optimal] [--horizon]
//! reports requested heap bytes separately from preloaded input; verify OUTPUT externally.
//! All ratio-lab builds of this example instrument allocations; do not compare their CPU.
//! Input I/O and verification are outside the creation timer. OUTPUT saves
//! the last stream/archive for independent byte comparison and RARLab tests.
#[cfg(feature = "ratio-lab")]
#[path = "bench_rar5_create/memory.rs"]
mod memory;
#[cfg(feature = "ratio-lab")]
#[global_allocator]
static ALLOCATOR: memory::Meter = memory::Meter;

use rars::codec::rar50::{self, DecodeMode, EncodeOptions, Unpack50Decoder};
use rars::rar50::{CompressedEntry, EncryptedStoredEntry, Rar50Writer, StoredEntry, WriterOptions};
use rars::{ArchiveReadOptions, ArchiveReader, ArchiveVersion, FeatureSet};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Instant;

struct Capture(Arc<Mutex<Vec<u8>>>);
impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    #[cfg(feature = "ratio-lab")]
    if args.get(1).is_some_and(|s| s == "--writer-memory") {
        memory::run(&args);
        return;
    }
    let limit: u64 = args[2].parse().unwrap();
    let rounds: usize = args[3].parse().unwrap();
    let mode = args.get(4).map(String::as_str).unwrap_or("lz");
    let mut data = Vec::new();
    std::fs::File::open(&args[1])
        .unwrap()
        .take(limit)
        .read_to_end(&mut data)
        .unwrap();
    let encrypted = mode == "encrypted" || mode == "headers";
    let mut reference = None;
    for round in 0..=rounds {
        let start = Instant::now();
        let encoded = match mode {
            "lz" => rar50::encode_lz_member_with_options(&data, 0, EncodeOptions::new(16)).unwrap(),
            "literal" => rar50::encode_literal_only(&data, 0).unwrap(),
            "archive" => Rar50Writer::new(WriterOptions::new(
                ArchiveVersion::Rar50,
                FeatureSet::default(),
            ))
            .compressed_entries(&[CompressedEntry {
                name: b"payload.bin",
                data: &data,
                mtime: None,
                attributes: 0,
                host_os: 3,
            }])
            .finish()
            .unwrap(),
            "store" => Rar50Writer::new(WriterOptions::new(
                ArchiveVersion::Rar50,
                FeatureSet::default(),
            ))
            .stored_entries(&[StoredEntry {
                name: b"payload.bin",
                data: &data,
                mtime: None,
                attributes: 0,
                host_os: 3,
            }])
            .finish()
            .unwrap(),
            "encrypted" | "headers" => {
                let mut features = FeatureSet::default();
                features.file_encryption = true;
                features.header_encryption = mode == "headers";
                Rar50Writer::new(WriterOptions::new(ArchiveVersion::Rar50, features))
                    .encrypted_stored_entries(&[EncryptedStoredEntry {
                        name: b"payload.bin",
                        data: &data,
                        mtime: None,
                        attributes: 0,
                        host_os: 3,
                        password: b"benchpw",
                    }])
                    .finish()
                    .unwrap()
            }
            _ => panic!("unknown mode"),
        };
        let seconds = start.elapsed().as_secs_f64();
        let crc = crc32fast::hash(&encoded);
        if !encrypted {
            assert_eq!(
                *reference.get_or_insert((encoded.len(), crc)),
                (encoded.len(), crc)
            );
        }
        if mode == "lz" || mode == "literal" {
            let decoded = Unpack50Decoder::new()
                .decode_member(&encoded, 0, data.len(), false, DecodeMode::Lz)
                .unwrap();
            assert_eq!(decoded, data);
        } else {
            let options = if encrypted {
                ArchiveReadOptions::with_password(b"benchpw")
            } else {
                ArchiveReadOptions::default()
            };
            let archive = ArchiveReader::read_owned_with_options(encoded.clone(), options).unwrap();
            let decoded = Arc::new(Mutex::new(Vec::new()));
            archive
                .extract_to_with_options(options, |_| {
                    Ok(Box::new(Capture(decoded.clone())) as Box<dyn Write>)
                })
                .unwrap();
            assert_eq!(*decoded.lock().unwrap(), data);
        }
        if round != 0 {
            println!(
                "round={round} mode={mode} input={} packed={} crc={crc:08x} seconds={seconds:.9}",
                data.len(),
                encoded.len()
            );
        }
        if round == rounds {
            if let Some(path) = args.get(5) {
                std::fs::write(path, &encoded).unwrap();
            }
        }
    }
}
