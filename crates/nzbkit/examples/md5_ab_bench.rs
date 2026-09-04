//! A/B the crate's MD5 (`nzbkit::md5fast::Md5`) against the `md-5` crate,
//! in one process, interleaved.
//!
//! This exists because the choice between the two is a compile-time
//! `cfg` (see `md5fast`'s header), so "before and after" would otherwise
//! mean two binaries and two build clocks - and on the Windows rigs that
//! is 3 to 20 minutes an arm, with the box's state moving underneath.
//! One binary that runs both arms back to back, several times, removes
//! every question about which build produced which number.
//!
//! On Windows x86-64 arm A is this crate's inline-assembly block
//! function and arm B is `md-5`'s portable Rust one - the comparison the
//! 2 Sep 2026 PAR2 audit's section 6 item 0c asks for. On ARM64 macOS
//! and Linux arm A is AWS-LC's assembly block function and arm B is the
//! same portable `md-5`. On every other target the two arms are the same
//! code and the run is a noise floor, which is itself worth printing: it
//! says how much of any delta is method rather than implementation.
//!
//! Shape copied from `sysbench::compute` deliberately, so the per-core
//! figure here is comparable with `nzbfast bench-cpu`'s md5 line: 1 MiB
//! chunks, one-shot digests, single thread then one thread per core.
//!
//!   cargo run --release -p nzbkit --example md5_ab_bench [-- <MiB> <reps>]

use std::hint::black_box;
use std::time::Instant;

fn payload(bytes: usize) -> Vec<u8> {
    // xorshift64*, so the corpus is the same on every box and every run.
    let mut s: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut v = vec![0u8; bytes];
    for b in v.iter_mut() {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        *b = (s >> 33) as u8;
    }
    v
}

fn timed(p: &[u8], cores: usize, f: &(dyn Fn(&[u8]) + Sync)) -> (f64, f64) {
    let t0 = Instant::now();
    f(p);
    let one = p.len() as f64 / t0.elapsed().as_secs_f64() / 1e9;
    let t0 = Instant::now();
    std::thread::scope(|s| {
        for _ in 0..cores {
            s.spawn(|| f(p));
        }
    });
    let all = (p.len() * cores) as f64 / t0.elapsed().as_secs_f64() / 1e9;
    (one, all)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mib: usize = args.first().and_then(|a| a.parse().ok()).unwrap_or(256);
    let reps: usize = args.get(1).and_then(|a| a.parse().ok()).unwrap_or(3);
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
    let p = payload(mib << 20);

    let ours = |p: &[u8]| {
        use nzbkit::md5fast::{Digest, Md5};
        for c in p.chunks(1 << 20) {
            let d: [u8; 16] = Md5::digest(c).into();
            black_box(d);
        }
    };
    let refr = |p: &[u8]| {
        use md5::{Digest, Md5};
        for c in p.chunks(1 << 20) {
            let d: [u8; 16] = Md5::digest(c).into();
            black_box(d);
        }
    };

    // Correctness before speed: a fast wrong hash is worth nothing, and
    // this prints on the same box that produced the timings.
    {
        use md5::Digest as _;
        for n in [
            0usize,
            1,
            55,
            56,
            63,
            64,
            65,
            119,
            120,
            1000,
            1 << 20,
            p.len(),
        ] {
            let a: [u8; 16] =
                <nzbkit::md5fast::Md5 as nzbkit::md5fast::Digest>::digest(&p[..n]).into();
            let b: [u8; 16] = md5::Md5::digest(&p[..n]).into();
            assert_eq!(a, b, "md5 mismatch at len {n}");
        }
        println!("AGREE ours == md-5 over 12 lengths up to {} MiB", mib);
    }

    println!("cpu cores={cores} payload={mib} MiB reps={reps}  (GB/s, higher is better)");
    // One untimed pass of each arm first: the page cache, the thread
    // pool and the clock are all cold on rep 1 otherwise, and on a
    // 32-core box that alone moved an all-core figure 19% between two
    // reps of the SAME code.
    timed(&p, cores, &ours);
    timed(&p, cores, &refr);

    let mut best = (0.0f64, 0.0f64, 0.0f64, 0.0f64);
    for r in 1..=reps {
        let (o1, oa) = timed(&p, cores, &ours);
        let (r1, ra) = timed(&p, cores, &refr);
        println!(
            "REP {r} ours 1c={o1:.3} all={oa:.3} | md-5 1c={r1:.3} all={ra:.3} | \
             delta 1c={:+.1}% all={:+.1}%",
            (o1 / r1 - 1.0) * 100.0,
            (oa / ra - 1.0) * 100.0
        );
        best = (
            best.0.max(o1),
            best.1.max(oa),
            best.2.max(r1),
            best.3.max(ra),
        );
    }
    println!(
        "BEST ours 1c={:.3} all={:.3} | md-5 1c={:.3} all={:.3} | delta 1c={:+.1}% all={:+.1}%",
        best.0,
        best.1,
        best.2,
        best.3,
        (best.0 / best.2 - 1.0) * 100.0,
        (best.1 / best.3 - 1.0) * 100.0
    );
}
