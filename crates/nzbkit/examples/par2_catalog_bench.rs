//! B2 packet-catalog A/B harness: generate a multi-set PAR2 directory
//! with damage, then time the settle-tail sequence
//! (`repair_present_sets`, then `covered_names`, then
//! `sniffed_packet_files`) through the public free functions only - so
//! the SAME file builds against the pre-catalog baseline commit for the
//! A leg and against the catalog for the B leg.
//!
//!   cargo run --release -p nzbkit --example par2_catalog_bench -- \
//!       <dir> gen <sets> <data_mib_per_set> <bulk_mib_per_set>
//!   cargo run --release -p nzbkit --example par2_catalog_bench -- \
//!       <dir> run <sets_expected>
//!
//! `gen` writes, per set: one data file, an index .par2, a volume
//! carrying 4 REAL recovery slices (exponents 0-3), and bulk volumes of
//! valid-MD5 RecvSlic packets at high exponents whose payloads are
//! noise - the repair selects the smallest exponents, so the bulk is
//! scanned (the cost under test) but never selected. One extra bulk
//! volume per set ships under an extensionless hash name to exercise
//! the sniff path. Two blocks of each data file are corrupted, so every
//! set really repairs. `run` performs the sequence once and prints
//! wall/CPU/maxrss plus the outcome digest; damage is re-inflicted
//! first so back-to-back runs measure the same work.

use md5::{Digest, Md5};
use nzbkit::gf16::{self, MulTable};
use nzbkit::par2repair::{RepairStatus, input_base_logs};
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 8] = b"PAR2\0PKT";
const T_MAIN: &[u8; 16] = b"PAR 2.0\0Main\0\0\0\0";
const T_FILEDESC: &[u8; 16] = b"PAR 2.0\0FileDesc";
const T_IFSC: &[u8; 16] = b"PAR 2.0\0IFSC\0\0\0\0";
const T_RECVSLIC: &[u8; 16] = b"PAR 2.0\0RecvSlic";
const BS: usize = 1 << 19; // 512 KiB blocks

fn pkt(set_id: [u8; 16], ptype: &[u8; 16], body: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(MAGIC);
    p.extend_from_slice(&(64 + body.len() as u64).to_le_bytes());
    p.extend_from_slice(&[0u8; 16]);
    p.extend_from_slice(&set_id);
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

fn index_bytes(set_id: [u8; 16], name: &str, data: &[u8]) -> Vec<u8> {
    let fid = [set_id[0], 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut main = Vec::new();
    main.extend_from_slice(&(BS as u64).to_le_bytes());
    main.extend_from_slice(&1u32.to_le_bytes());
    main.extend_from_slice(&fid);
    let mut out = pkt(set_id, T_MAIN, &main);
    let mut desc = Vec::new();
    desc.extend_from_slice(&fid);
    desc.extend_from_slice(&<[u8; 16]>::from(Md5::digest(data)));
    desc.extend_from_slice(&<[u8; 16]>::from(Md5::digest(
        &data[..data.len().min(16384)],
    )));
    desc.extend_from_slice(&(data.len() as u64).to_le_bytes());
    let mut nb = name.as_bytes().to_vec();
    while !nb.len().is_multiple_of(4) {
        nb.push(0);
    }
    desc.extend_from_slice(&nb);
    out.extend(pkt(set_id, T_FILEDESC, &desc));
    let mut ifsc = fid.to_vec();
    for chunk in data.chunks(BS) {
        let mut padded = chunk.to_vec();
        padded.resize(BS, 0);
        ifsc.extend_from_slice(&<[u8; 16]>::from(Md5::digest(&padded)));
        ifsc.extend_from_slice(&crc32fast::hash(&padded).to_le_bytes());
    }
    out.extend(pkt(set_id, T_IFSC, &ifsc));
    out
}

fn real_volume(set_id: [u8; 16], data: &[u8], exps: &[u32]) -> Vec<u8> {
    let slices: Vec<Vec<u8>> = data
        .chunks(BS)
        .map(|c| {
            let mut v = c.to_vec();
            v.resize(BS, 0);
            v
        })
        .collect();
    let logs = input_base_logs(slices.len()).unwrap();
    let mut out = Vec::new();
    for &e in exps {
        let mut acc = vec![0u16; BS / 2];
        for (d, &k) in slices.iter().zip(&logs) {
            MulTable::new(gf16::pow2(k as u64 * e as u64)).xor_mul_into(&mut acc, d);
        }
        let mut body = e.to_le_bytes().to_vec();
        body.extend(acc.iter().flat_map(|w| w.to_le_bytes()));
        out.extend(pkt(set_id, T_RECVSLIC, &body));
    }
    out
}

/// Valid-MD5 RecvSlic packets at high exponents over noise payloads:
/// scan cost without GF generation cost, never selected by a repair.
fn bulk_volume(set_id: [u8; 16], first_exp: u32, n: usize, seed: u64) -> Vec<u8> {
    let mut out = Vec::new();
    for i in 0..n {
        let mut body = (first_exp + i as u32).to_le_bytes().to_vec();
        body.extend(payload(BS, seed ^ (i as u64) << 7));
        out.extend(pkt(set_id, T_RECVSLIC, &body));
    }
    out
}

fn inflict(dir: &Path, sets: usize) {
    use std::io::{Seek, SeekFrom, Write};
    for s in 0..sets {
        let p = dir.join(format!("data{s}.bin"));
        let mut f = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
        for blk in [0u64, 2] {
            f.seek(SeekFrom::Start(blk * BS as u64 + 17)).unwrap();
            f.write_all(b"\xde\xad").unwrap();
        }
    }
}

fn rusage() -> (f64, f64, i64) {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    let s = ru.ru_utime.tv_sec as f64 + ru.ru_utime.tv_usec as f64 / 1e6;
    let y = ru.ru_stime.tv_sec as f64 + ru.ru_stime.tv_usec as f64 / 1e6;
    (s, y, ru.ru_maxrss)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = PathBuf::from(&args[1]);
    match args[2].as_str() {
        "gen" => {
            let sets: usize = args[3].parse().unwrap();
            let data_mib: usize = args[4].parse().unwrap();
            let bulk_mib: usize = args[5].parse().unwrap();
            std::fs::create_dir_all(&dir).unwrap();
            for s in 0..sets {
                let set_id = [s as u8 + 1; 16];
                let data = payload(data_mib << 20, s as u64 + 1);
                let name = format!("data{s}.bin");
                std::fs::write(dir.join(&name), &data).unwrap();
                std::fs::write(
                    dir.join(format!("set{s}.par2")),
                    index_bytes(set_id, &name, &data),
                )
                .unwrap();
                std::fs::write(
                    dir.join(format!("set{s}.vol00+4.par2")),
                    real_volume(set_id, &data, &[0, 1, 2, 3]),
                )
                .unwrap();
                let bulk_slices = (bulk_mib << 20) / (BS + 68);
                let half = bulk_slices / 2;
                std::fs::write(
                    dir.join(format!("set{s}.vol04+{half}.par2")),
                    bulk_volume(set_id, 1000, half, 0xb0 + s as u64),
                )
                .unwrap();
                // The other half under a hash name: sniff-path bulk.
                std::fs::write(
                    dir.join(format!("{:016x}", 0xabcd_0000u64 + s as u64)),
                    bulk_volume(set_id, 2000, bulk_slices - half, 0xc0 + s as u64),
                )
                .unwrap();
            }
            inflict(&dir, sets);
            println!("generated {sets} set(s) in {}", dir.display());
        }
        "run" => {
            let sets: usize = args[3].parse().unwrap();
            inflict(&dir, sets);
            let (u0, s0, _) = rusage();
            let t0 = std::time::Instant::now();
            let results = nzbkit::par2repair::repair_present_sets(&dir).unwrap();
            let repaired = results
                .iter()
                .filter(|r| matches!(r.status, Ok(RepairStatus::Repaired(_))))
                .count();
            let names = nzbkit::par2repair::covered_names(&dir).unwrap();
            let sniffed = nzbkit::par2repair::sniffed_packet_files(&dir).unwrap();
            let wall = t0.elapsed();
            let (u1, s1, rss) = rusage();
            assert_eq!(results.len(), sets, "every set qualifies");
            assert_eq!(repaired, sets, "every set repaired");
            println!(
                "sets={sets} repaired={repaired} names={} sniffed={} wall={:.3}s user={:.3}s sys={:.3}s maxrss={}MB",
                names.len(),
                sniffed.len(),
                wall.as_secs_f64(),
                u1 - u0,
                s1 - s0,
                rss / (1 << 20),
            );
        }
        other => panic!("unknown mode {other}"),
    }
}
