//! B3-stage-2 A/B harness: the mapped repair fed by the old
//! harvest-everything corpus (`repair_mapped` over slices copied whole
//! into memory, the shape crates/nzbfast/src/repair.rs shipped until
//! B3 stage 2) versus the catalog's locator-backed pread
//! (`repair_mapped_catalog`). Same directory, same damage, same
//! verdict; the difference under test is bytes resident and time.
//!
//!   cargo run --release -p nzbkit --example par2_mapped_locator_bench -- \
//!       <dir> gen <data_mib> <missing> <bulk_mib>
//!   cargo run --release -p nzbkit --example par2_mapped_locator_bench -- \
//!       <dir> run <harvest|catalog> <data_mib> <missing>
//!
//! Run each mode in its own process: maxrss is a process high-water
//! mark. `gen` writes the data file, a volume with REAL recovery for
//! the `missing` smallest exponents, and bulk volumes of valid-MD5
//! noise slices at high exponents - scanned and (in harvest mode)
//! copied resident, but never selected.

use md5::{Digest, Md5};
use nzbkit::gf16::{self, MulTable};
use nzbkit::par2::Par2File;
use nzbkit::par2repair::{
    PacketCatalog, VolumeIo, input_base_logs, recovery_slice_locators, repair_mapped,
    repair_mapped_catalog,
};
use std::path::PathBuf;

const MAGIC: &[u8; 8] = b"PAR2\0PKT";
const T_RECVSLIC: &[u8; 16] = b"PAR 2.0\0RecvSlic";
const BS: usize = 1 << 19; // 512 KiB blocks
const SET: [u8; 16] = [7u8; 16];

fn pkt(ptype: &[u8; 16], body: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(MAGIC);
    p.extend_from_slice(&(64 + body.len() as u64).to_le_bytes());
    p.extend_from_slice(&[0u8; 16]);
    p.extend_from_slice(&SET);
    p.extend_from_slice(ptype);
    p.extend_from_slice(body);
    let md5: [u8; 16] = Md5::digest(&p[32..]).into();
    p[16..32].copy_from_slice(&md5);
    p
}

fn payload(len: usize, seed: u64) -> Vec<u8> {
    let mut s = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s >> 24) as u8
        })
        .collect()
}

fn data_of(data_mib: usize) -> Vec<u8> {
    payload(data_mib << 20, 42)
}

struct Io {
    f: std::fs::File,
}
impl VolumeIo for Io {
    fn read(&self, _file: usize, off: u64, buf: &mut [u8]) -> std::io::Result<()> {
        use std::os::unix::fs::FileExt;
        self.f.read_exact_at(buf, off)
    }
    fn write(&self, _file: usize, off: u64, data: &[u8]) -> std::io::Result<()> {
        use std::os::unix::fs::FileExt;
        self.f.write_all_at(data, off)
    }
}

fn rusage() -> (f64, i64) {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    (
        ru.ru_utime.tv_sec as f64
            + ru.ru_utime.tv_usec as f64 / 1e6
            + ru.ru_stime.tv_sec as f64
            + ru.ru_stime.tv_usec as f64 / 1e6,
        ru.ru_maxrss,
    )
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = PathBuf::from(&args[1]);
    match args[2].as_str() {
        "gen" => {
            let data_mib: usize = args[3].parse().unwrap();
            let missing: usize = args[4].parse().unwrap();
            let bulk_mib: usize = args[5].parse().unwrap();
            std::fs::create_dir_all(&dir).unwrap();
            let data = data_of(data_mib);
            std::fs::write(dir.join("payload.bin"), &data).unwrap();
            let slices: Vec<Vec<u8>> = data
                .chunks(BS)
                .map(|c| {
                    let mut v = c.to_vec();
                    v.resize(BS, 0);
                    v
                })
                .collect();
            let logs = input_base_logs(slices.len()).unwrap();
            let mut real = Vec::new();
            for e in 0..missing as u32 {
                let mut acc = vec![0u16; BS / 2];
                for (d, &k) in slices.iter().zip(&logs) {
                    MulTable::new(gf16::pow2(k as u64 * e as u64)).xor_mul_into(&mut acc, d);
                }
                let mut body = e.to_le_bytes().to_vec();
                body.extend(acc.iter().flat_map(|w| w.to_le_bytes()));
                real.extend(pkt(T_RECVSLIC, &body));
            }
            std::fs::write(dir.join("real.vol.par2"), real).unwrap();
            let bulk_slices = (bulk_mib << 20) / (BS + 68);
            let mut bulk = Vec::new();
            for i in 0..bulk_slices {
                let mut body = (10_000 + i as u32).to_le_bytes().to_vec();
                body.extend(payload(BS, 0xbb ^ (i as u64) << 9));
                bulk.extend(pkt(T_RECVSLIC, &body));
            }
            std::fs::write(dir.join("bulk.vol.par2"), bulk).unwrap();
            println!(
                "generated: {} MiB data, {missing} real slice(s), {} bulk slice(s)",
                data_mib, bulk_slices
            );
        }
        "run" => {
            let mode = args[3].as_str();
            let data_mib: usize = args[4].parse().unwrap();
            let missing: usize = args[5].parse().unwrap();
            let data = data_of(data_mib);
            let n = data.len().div_ceil(BS);
            // First `missing` blocks read as absent; the repair rebuilds
            // them into a scratch copy of the file with those blocks
            // zeroed, then the whole-file MD5 self-prove reads it back.
            let mut present = vec![true; n];
            let mut damaged = data.clone();
            for (b, p) in present.iter_mut().enumerate().take(missing) {
                *p = false;
                damaged[b * BS..(b + 1) * BS].fill(0);
            }
            let scratch = dir.join("scratch.bin");
            std::fs::write(&scratch, &damaged).unwrap();
            drop(damaged);
            let file = Par2File {
                file_id: [1u8; 16],
                name: "payload.bin".into(),
                length: data.len() as u64,
                md5: Md5::digest(&data).into(),
                md5_16k: Md5::digest(&data[..16384]).into(),
                blocks: Vec::new(),
            };
            drop(data);
            let files = vec![(file, present)];
            let io = Io {
                f: std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&scratch)
                    .unwrap(),
            };
            let t0 = std::time::Instant::now();
            let rebuilt = match mode {
                // The pre-B3-stage-2 ownership model, verbatim: read
                // every packet file whole, copy every valid slice of
                // the set into memory, hand the corpus to repair_mapped
                // (which pins it across the NTT-fallback window).
                "harvest" => {
                    let mut recovery: Vec<(u32, Vec<u8>)> = Vec::new();
                    let mut names: Vec<_> = std::fs::read_dir(&dir)
                        .unwrap()
                        .map(|e| e.unwrap().path())
                        .filter(|p| {
                            p.extension()
                                .is_some_and(|x| x.eq_ignore_ascii_case("par2"))
                        })
                        .collect();
                    names.sort();
                    for p in names {
                        let bytes = std::fs::read(&p).unwrap();
                        for (exp, off, len) in recovery_slice_locators(&bytes, &SET) {
                            if len == BS {
                                recovery.push((exp, bytes[off..off + len].to_vec()));
                            }
                        }
                    }
                    repair_mapped(&files, BS, &recovery, &io, false).unwrap()
                }
                "catalog" => {
                    let mut cat = PacketCatalog::build(&dir).unwrap();
                    repair_mapped_catalog(&files, BS, &mut cat, &SET, &io, false).unwrap()
                }
                other => panic!("unknown mode {other}"),
            };
            let wall = t0.elapsed();
            let (cpu, rss) = rusage();
            assert_eq!(rebuilt, missing);
            println!(
                "mode={mode} missing={missing} rebuilt={rebuilt} wall={:.3}s cpu={:.3}s maxrss={}MB",
                wall.as_secs_f64(),
                cpu,
                rss / (1 << 20),
            );
            let _ = std::fs::remove_file(&scratch);
        }
        other => panic!("unknown mode {other}"),
    }
}
